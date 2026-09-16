rule sig_20160517_e41e679edefb955d2bcbc586b8f6b716 {
  meta:
    description = "datamaliciousorder - file 20160517_e41e679edefb955d2bcbc586b8f6b716.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81dbb2634a6abf34a5ff991fa13caa1dec95bb146b1c35c58e0323be01b850b4"

  strings:
    $s1 = "var jqy='vp4ejlarnuudrloovw hcd3uddpimkjbyynncgyrghnezy1uyhritmrqctmfhmvz2isybgisfbkqpvipwu1x=eco1z\\'oecyvtcnrmoco1ujintixd2iwf" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   rceiobyo=r4+\"v\"+\"al\";   WScript.lister=5;   rceiobyo=\"\"+\"s\";   ww=232323;   }catch(x)" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}