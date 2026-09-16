import "pe"
rule INDICATOR_KB_CERT_82d224323efa65060b641f51fadfef02 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8dccf6ad21a58226521e36d7e5dbad133331c181"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAVAS INVESTMENTS PTY LTD" and
            (
                pe.signatures[i].serial == "82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02" or
                pe.signatures[i].serial == "00:82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02"    
            )
        )
}