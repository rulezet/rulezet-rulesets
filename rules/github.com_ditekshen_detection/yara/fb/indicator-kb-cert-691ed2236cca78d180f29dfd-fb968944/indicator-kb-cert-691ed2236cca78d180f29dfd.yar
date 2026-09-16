import "pe"
rule INDICATOR_KB_CERT_691ed2236cca78d180f29dfd {
    meta:
         author = "ditekSHen"
         thumbprint = "8c8a043f51bb8d59182fb268c0db2f1b9d876dbe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "COSMART LLC" and
            pe.signatures[i].issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
            pe.signatures[i].serial == "69:1e:d2:23:6c:ca:78:d1:80:f2:9d:fd"
        )
}