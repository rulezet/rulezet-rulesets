import "pe"
rule INDICATOR_KB_CERT_00e4e795fd1fd25595b869ce22aa7dc49f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "269f25e6b7c690ae094086bd7825d03b48d4fcb1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OASIS COURT LIMITED" and
            (
                pe.signatures[i].serial == "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or
                pe.signatures[i].serial == "e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
            )
        )
}