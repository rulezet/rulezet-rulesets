rule sig_20160517_69878b180fd78397735ec7c245905aa8 {
  meta:
    description = "datamaliciousorder - file 20160517_69878b180fd78397735ec7c245905aa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a44f762b55ddefe81a93cc8c8ef466cf0291a43188d7bd51ee28c7021b47ae0"

  strings:
    $s1 = "var bv4='vw4s2ralcqvurlnoqy wopplmxuwymxsnpvupqmxjnqpgtgbjtttdkcpq3hftsdakcrphthd=j3tlm\\'bawbltutfv1canrvznljdbyiowgcdfwufgfuzr" ascii
    $s2 = "ateObject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   us1cblm3xq=r4+\"v\"+\"al\";   WScript.lister=5;   us1cblm3xq=\"\"+\"s\";   ww=2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}