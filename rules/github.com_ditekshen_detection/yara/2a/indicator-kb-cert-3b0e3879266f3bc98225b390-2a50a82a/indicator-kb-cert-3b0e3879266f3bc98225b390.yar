import "pe"
rule INDICATOR_KB_CERT_3b0e3879266f3bc98225b390 {
    meta:
         author = "ditekSHen"
         thumbprint = "2eab64a4eaf37060d27620a822df2e1f18ac28f6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hangzhou Yueju Apparel Co., Ltd." and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "3b:0e:38:79:26:6f:3b:c9:82:25:b3:90"
        )
}