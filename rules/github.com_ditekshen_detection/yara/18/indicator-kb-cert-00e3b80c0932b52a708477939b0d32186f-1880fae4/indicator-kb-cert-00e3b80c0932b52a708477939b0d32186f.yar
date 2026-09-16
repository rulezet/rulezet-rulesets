import "pe"
rule INDICATOR_KB_CERT_00e3b80c0932b52a708477939b0d32186f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1d2b5d4f0de1d7ce4abf82fdc58adc43bc28adee"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and
            (
                pe.signatures[i].serial == "e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or
                pe.signatures[i].serial == "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
            )
        )
}