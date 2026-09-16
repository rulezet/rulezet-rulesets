import "pe"
rule INDICATOR_KB_CERT_708737c791c878d6dd7b7c43 {
    meta:
         author = "ditekSHen"
         thumbprint = "7ed7081ee612fbf9fe0ade46f4a2749da20251e0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Langfang Alkem Material Technology Co., Ltd." and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "70:87:37:c7:91:c8:78:d6:dd:7b:7c:43"
        )
}