rule _20160921_0550bef558fba79f944112d34861e4ec_20160921_17ed90b369ab_2222 {
  meta:
    description = "datamaliciousorder - from files 20160921_0550bef558fba79f944112d34861e4ec.js, 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_e432cba10cde369693d6b125dda112c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cc46901b4b691df366f68f1812df531215964f5150686b06997f1f49b536a1c"
    hash2       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash3       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash4       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash5       = "0f0aa2d80d649fb44a67c6ec77b95eb26709057f543ca215edf15a9bcc4bae4b"

  strings:
    $s1 = "on f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"" ascii
    $s2 = "00(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um" ascii
    $s3 = "(),(function f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"QDg\";})(),(function f000(" ascii
    $s4 = "function f000(){return \"ZIi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(functio" ascii
    $s6 = "f000(){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb" ascii
    $s7 = "turn \"WIj\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(f" ascii
    $s8 = "){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}