import "pe"
rule INDICATOR_KB_CERT_dca9012634e8b609884fe9284d30eff5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "60971c18c7efb4a294f1d8ee802ff3d581c77834"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bebaeefaeba" and (
                pe.signatures[i].serial == "dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5" or
                pe.signatures[i].serial == "00:dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5"    
            )
        )
}