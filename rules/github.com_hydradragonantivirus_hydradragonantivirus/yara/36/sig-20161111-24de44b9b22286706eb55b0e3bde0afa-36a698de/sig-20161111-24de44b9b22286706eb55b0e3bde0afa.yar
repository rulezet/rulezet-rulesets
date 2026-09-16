rule sig_20161111_24de44b9b22286706eb55b0e3bde0afa {
  meta:
    description = "datamaliciousorder - file 20161111_24de44b9b22286706eb55b0e3bde0afa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2631f1401fce23945648f6e00ca9b99dccae333e89bac4904e027de06adca911"

  strings:
    $s1 = "    var JSv3 = [YPu0 + \"coolnshop.com/ykga5p\",YPu0 + \"nepeanfinearts.com/yd64fsvl\",YPu0 + \"eddermiaul.net/4hz27zup\",YPu0 +" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}