rule sig_20160517_547ef1edeef7f37a455956f0d75eef59 {
  meta:
    description = "datamaliciousorder - file 20160517_547ef1edeef7f37a455956f0d75eef59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26743535882ebba2d7cfc79ec89cea3603b061cda15c41faea88feb48fc74456"

  strings:
    $s1 = "var jqy='vp4ejlarnuudrloovw hcd3uddpimkjbyynncgyrghnezy1uyhritmrqctmfhmvz2isybgisfbkqpvipwu1x=eco1z\\'oecyvtcnrmoco1ujintixd2iwf" ascii
    $s2 = "S\"+\"cript\"+\".RegE\"+\"xp\");   rceiobyo=r4+\"v\"+\"al\";   WScript.lister=5;   rceiobyo=\"\"+\"s\";   ww=232323;   }catch(x)" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}