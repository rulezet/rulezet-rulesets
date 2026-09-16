rule sig_20160328_cfa0f973d5fd18a180a3c504f838471f {
  meta:
    description = "datamaliciousorder - file 20160328_cfa0f973d5fd18a180a3c504f838471f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bd02cf3e465c3593e35661f64a48083e33a3d284171d449baacd1412c8835f5"

  strings:
    $x1  = "eval(assert(\"var%20rcleanScript%20%3D%20%28%22WScri%22%29%3Bvar%20clone%20%3D%20%28%22se%22%29%2C%20hasContent%20%3D%20%2818%29" ascii
    $s2  = "eval(assert(\"var%20rcleanScript%20%3D%20%28%22WScri%22%29%3Bvar%20clone%20%3D%20%28%22se%22%29%2C%20hasContent%20%3D%20%2818%29" ascii
    $s3  = "letter[oldCache + \"pe\"] = ((script | 32) - (write + 31));" fullword ascii
    $s4  = "while(createTween[camelCase + \"dySt\" + valueIsBorderBox] != ((15 + MAX_NEGATIVE) - (52 | hasContent))) siblings[\"WSc\" + sort" ascii
    $s5  = "while(createTween[camelCase + \"dySt\" + valueIsBorderBox] != ((15 + MAX_NEGATIVE) - (52 | hasContent))) siblings[\"WSc\" + sort" ascii
    $s6  = "curElem(assert(\"booleans%20%3D%20siblings%5B%22WScrip%22%20+%20done%5D%5B%22Creat%22%20+%20includeWidth%20+%20%22ct%22%5D%28rcl" ascii
    $s7  = "script%20%3D%20%2848%29%2C%20write%20%3D%20%2816%29%3Bconstructor%20%3D%20%283%29%3B%20always%20%3D%20%28%22http%3A%22%29%3B%20t" ascii
    $s8  = "for(optSelected = ((clearQueue - 42) & (bulk - 50)); optSelected < slideDown[\"l\" + nextAll + \"ngt\" + access]; optSelected++)" ascii
    $s9  = "curElem(assert(\"createTween%5Bsetup%20+%20%22p%22%20+%20nextAll%20+%20%22n%22%5D%28token%20+%20%22ET%22%2C%20first%20+%20%22/re" ascii
    $s10 = "curElem(assert(\"slideDown%20%3D%20%5B%22Msxm%22%20+%20iframe%20+%20%22ver%22%20+%20contentType%20+%20%22TP.6.%22%20+%20collecti" ascii
    $s11 = "curElem(assert(\"mapped%20%3D%20booleans%5B%22Expa%22%20+%20what%20+%20%22iro%22%20+%20settings%20+%20%22tring%22%20+%20overwrit" ascii
    $s12 = "letter[\"m\" + setup + \"de\"] = ((241, createComment, 2, constructor) | 3);" fullword ascii
    $s13 = "s[completed + \"ipt\"][eventDoc + \"p\"](((2878 & tokenCache) + (3706 & file)));" fullword ascii
    $s14 = "getJSON(_jQuery, collection);" fullword ascii
    $s15 = "status(hasContent, first);" fullword ascii
    $s16 = "letter[\"Sav\" + getElementsByClassName + \"e\"](mapped, (2 & rheader));" fullword ascii
    $s17 = "bySet(contentType, innerHTML, submit, nextAll);" fullword ascii
    $s18 = "createTween[clone + \"nd\"]();" fullword ascii
    $s19 = "curElem(assert(\"slideDown%20%3D%20%5B%22Msxm%22%20+%20iframe%20+%20%22ver%22%20+%20contentType%20+%20%22TP.6.%22%20+%20collecti" ascii
    $s20 = "letter[setup + \"pe\" + rmultiDash]();" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    1 of ($x*) and 4 of them
}