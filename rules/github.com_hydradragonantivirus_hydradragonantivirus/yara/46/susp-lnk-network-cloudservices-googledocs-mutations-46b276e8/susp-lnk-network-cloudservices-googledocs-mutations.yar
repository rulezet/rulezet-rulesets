rule SUSP_LNK_Network_CloudServices_GoogleDocs_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $docsgooglecom_base64              = "docs.google.com" base64 base64wide
    $docsgooglecom_xor                 = "docs.google.com" xor(0x01-0xff) ascii wide
    $docsgooglecom_flipflop            = "odscg.oolg.eocm" nocase ascii wide
    $docsgooglecom_reverse             = "moc.elgoog.scod" nocase ascii wide
    $docsgooglecom_hex_enc_str         = "646f63732e676f6f676c652e636f6d" nocase ascii wide
    $docsgooglecom_decimal             = "100 111 99 115 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    $docsgooglecom_fallchill           = "wlxh.tlltov.xln" nocase ascii wide
    $docsgooglecom_stackpush           = "hcomhgle.h.goohdocs" nocase ascii wide
    $docsgooglecom_stackpushnull       = "hcom\x00hgle.h.goohdocs"
    $docsgooglecom_stackpushdoublenull = "hcom\x00\x00hgle.h.goohdocs"

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}