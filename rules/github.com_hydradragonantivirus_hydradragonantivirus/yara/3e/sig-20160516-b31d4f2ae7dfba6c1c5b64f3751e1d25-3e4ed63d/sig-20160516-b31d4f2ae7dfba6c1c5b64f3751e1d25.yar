rule sig_20160516_b31d4f2ae7dfba6c1c5b64f3751e1d25 {
  meta:
    description = "datamaliciousorder - file 20160516_b31d4f2ae7dfba6c1c5b64f3751e1d25.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "078a4084abfd24e3a0f80771b33a408196a0ad237b4333307b161338dd2a1ca3"

  strings:
    $s1 = "var ova='veht1naalyftrcgve4 usbotom3aycmibaoehgmp3nywd3bnuacxrlmatdcias1kbzdlpawd=kcu3f\\'dfmkltggs32cg4vlfnhmfsriqkhjgfwwmjyuuv" ascii
    $s2 = "cript\"+\".RegE\"+\"xp\");   ubbm2ysu=r4+\"v\"+\"al\";   WScript.lister=5;   ubbm2ysu=\"\"+\"s\";   ww=232323;   }catch(x){}   w" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}