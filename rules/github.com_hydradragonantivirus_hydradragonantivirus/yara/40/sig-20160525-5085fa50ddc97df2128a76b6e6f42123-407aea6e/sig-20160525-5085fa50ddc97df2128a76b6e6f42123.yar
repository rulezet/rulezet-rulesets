rule sig_20160525_5085fa50ddc97df2128a76b6e6f42123 {
  meta:
    description = "datamaliciousorder - file 20160525_5085fa50ddc97df2128a76b6e6f42123.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3306472eab22aade2778dcda30531b638fc88c516fb58f04837e3d874e2ce74"

  strings:
    $s1 = "dare + me+dnenoisilloce+)eixode(gsme + imd+)tsilslianbmuhtod(cthd + ssorcad + sdnetd+modnard + ecapsetihwxelfd+md + )dnenoisillo" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}