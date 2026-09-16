rule sig_20160311_6226d2402571bb2ca4008fcb7ab66941 {
  meta:
    description = "datamaliciousorder - file 20160311_6226d2402571bb2ca4008fcb7ab66941.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "299e5fcfa6ec5084a286f0cf945b374c3332ea9e41894d63fc4e2b71fecbbda0"

  strings:
    $x1  = "content[outermost + \"e\" + isLocal](\"G\".rquickExpr() + click, \"http:\" + valueParts + \"eter\" + interval + \"em.co\".rquick" ascii
    $s2  = "content[outermost + \"e\" + isLocal](\"G\".rquickExpr() + click, \"http:\" + valueParts + \"eter\" + interval + \"em.co\".rquick" ascii
    $s3  = " & qsaError) | (Math.pow(492, Deferred) - 241312)) / ((unit / 5) * (dir, 65, Deferred) + (5 + rnative))), (((2176 | documentIsHT" ascii
    $s4  = "innerHTML = optgroup[\"Expan\" + getter + \"viron\".rquickExpr() + el + \"tStr\" + duplicates](\"%TEMP\" + removeClass) + \"glob" ascii
    $s5  = "content = doc[\"WScrip\".rquickExpr() + rsubmitterTypes][\"Crea\" + elementMatcher + \"ject\"](rinputs + \"L2.XML\".rquickExpr()" ascii
    $s6  = "innerHTML = optgroup[\"Expan\" + getter + \"viron\".rquickExpr() + el + \"tStr\" + duplicates](\"%TEMP\" + removeClass) + \"glob" ascii
    $s7  = "content = doc[\"WScrip\".rquickExpr() + rsubmitterTypes][\"Crea\" + elementMatcher + \"ject\"](rinputs + \"L2.XML\".rquickExpr()" ascii
    $s8  = "ast + \"7745\" + propFix, !(((((Math.pow(15, Deferred) - 208) * (noConflict * 3) - (Math.pow((unqueued - 20), (win / 4)) - (tupl" ascii
    $s9  = " & (sourceIndex, 213, resolve)), (1 + (noConflict * 1))) - ((createComment | 5123) * (fadeIn / 13) + (actualDisplay - 2163))), (" ascii
    $s10 = "ML) / (7 + animation)) - (Math.pow((2 + not), (0 | Deferred)) - 5 * timeStamp * 13)))) == win));" fullword ascii
    $s11 = "content[\"s\" + box + \"nd\".rquickExpr()]();" fullword ascii
    $s12 = "((charset * 8 + rclickable) / (8 + rclickable)) * ((183, rsubmittable), (305 - inspect), (147 + nid), (49, setMatched))), (((690" ascii
    $s13 = "matcherIn[\"save\" + siblings + \"ile\".rquickExpr()](innerHTML, ((animation - 34) * Deferred));" fullword ascii
    $s14 = "checked[off + \"n\"](innerHTML.rquickExpr(((trim, 48, open) / (58 - reverse))), (0 & noConflict), (0 | (andSelf - 39)));" fullword ascii
    $s15 = "promise[support + \"ose\"]();" fullword ascii
    $s16 = "getter = \"dEn\"," fullword ascii
    $s17 = "matcherIn[outermost + \"en\"]();" fullword ascii
    $s18 = "clearCloneStyle[time + \"p\".rquickExpr() + box] = 1;" fullword ascii
    $s19 = "doc = ((2, (namespaces * 8 + reject), 3 * setFilters, (16 | rcheckableType)), ((3 * num) + (131, ontype, 32, currentValue)), eva" ascii
    $s20 = "doc = ((2, (namespaces * 8 + reject), 3 * setFilters, (16 | rcheckableType)), ((3 * num) + (131, ontype, 32, currentValue)), eva" ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}