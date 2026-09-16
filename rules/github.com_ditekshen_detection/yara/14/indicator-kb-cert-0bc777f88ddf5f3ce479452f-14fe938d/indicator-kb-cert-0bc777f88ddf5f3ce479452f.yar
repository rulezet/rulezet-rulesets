import "pe"
rule INDICATOR_KB_CERT_0bc777f88ddf5f3ce479452f {
    meta:
         author = "ditekSHen"
         thumbprint = "55aa40dea5621f0c0fbc8b9dd8066ff2290a7e82"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ARION LLC" and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "0b:c7:77:f8:8d:df:5f:3c:e4:79:45:2f"
        )
}