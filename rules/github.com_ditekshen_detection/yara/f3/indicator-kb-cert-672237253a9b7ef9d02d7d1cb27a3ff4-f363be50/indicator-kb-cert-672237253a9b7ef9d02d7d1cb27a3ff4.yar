import "pe"
rule INDICATOR_KB_CERT_672237253a9b7ef9d02d7d1cb27a3ff4 {
    meta:
         author = "ditekSHen"
         thumbprint = "36a0f423c1fa48f172e4fecd06b8099f0ebbaeb8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foshan Yongqiheng Trading Co., Ltd." and
            pe.signatures[i].issuer contains "Certum Extended Validation Code Signing 2021 CA" and
            pe.signatures[i].serial == "67:22:37:25:3a:9b:7e:f9:d0:2d:7d:1c:b2:7a:3f:f4"
        )
}