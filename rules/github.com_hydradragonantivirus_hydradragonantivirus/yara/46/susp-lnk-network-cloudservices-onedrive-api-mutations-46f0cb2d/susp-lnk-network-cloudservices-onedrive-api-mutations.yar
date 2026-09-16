rule SUSP_LNK_Network_CloudServices_OneDrive_API_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $apilivecom_base64              = "api.live.com" base64 base64wide
    $apilivecom_xor                 = "api.live.com" xor(0x01-0xff) ascii wide
    $apilivecom_flipflop            = "pa.iilevc.mo" nocase ascii wide
    $apilivecom_reverse             = "moc.evil.ipa" nocase ascii wide
    $apilivecom_hex_enc_str         = "6170692e6c6976652e636f6d" nocase ascii wide
    $apilivecom_decimal             = "97 112 105 46 108 105 118 101 46 99 111 109" nocase ascii wide
    $apilivecom_fallchill           = "akr.orev.xln" nocase ascii wide
    $apilivecom_stackpush           = "h.comhlivehapi." nocase ascii wide
    $apilivecom_stackpushnull       = "h.com\x00hlivehapi."
    $apilivecom_stackpushdoublenull = "h.com\x00\x00hlivehapi."

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}