rule SUSP_LNK_Network_CloudServices_GoogleDrive_Mutations {
  meta:
    author      = "Greg Lesnewich"
    description = "check for LNK files referencing a common Cloud Service - this may be used to download additional components"
    date        = "2023-01-03"
    version     = "1.0"
    DaysofYARA  = "3/100"

  strings:
    $drivegooglecom_base64              = "drive.google.com" base64 base64wide
    $drivegooglecom_xor                 = "drive.google.com" xor(0x01-0xff) ascii wide
    $drivegooglecom_flipflop            = "rdvi.eoggoelc.mo" nocase ascii wide
    $drivegooglecom_reverse             = "moc.elgoog.evird" nocase ascii wide
    $drivegooglecom_hex_enc_str         = "64726976652e676f6f676c652e636f6d" nocase ascii wide
    $drivegooglecom_decimal             = "100 114 105 118 101 46 103 111 111 103 108 101 46 99 111 109" nocase ascii wide
    $drivegooglecom_fallchill           = "wirev.tlltov.xln" nocase ascii wide
    $drivegooglecom_stackpush           = "h.comhoglehe.gohdriv" nocase ascii wide
    $drivegooglecom_stackpushnull       = "h.com\x00hoglehe.gohdriv"
    $drivegooglecom_stackpushdoublenull = "h.com\x00\x00hoglehe.gohdriv"

  condition:
    uint32be(0x0) == 0x4C000000 and
    1 of them
}