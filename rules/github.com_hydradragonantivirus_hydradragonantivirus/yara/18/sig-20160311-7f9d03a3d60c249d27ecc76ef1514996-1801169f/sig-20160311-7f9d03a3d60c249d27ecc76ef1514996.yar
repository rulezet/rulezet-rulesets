rule sig_20160311_7f9d03a3d60c249d27ecc76ef1514996 {
  meta:
    description = "datamaliciousorder - file 20160311_7f9d03a3d60c249d27ecc76ef1514996.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18beee56a4bc9e3d35f74a9fa2a7d2529ee2ca026bddc5c234fcd372ad434c13"

  strings:
    $s1  = "Expr[camelCase + \"p\" + propHooks](\"G\" + v + \"T\".check(), matcher + \"//p\" + tween + \"y_a\" + rprotocol + \"epub\".check(" ascii
    $s2  = "buildFragment = \"%TEMP%\"," fullword ascii
    $s3  = "matcher = \"http:\"," fullword ascii
    $s4  = " * handleObjIn * 2 | (animation & 114)) / (has * 2 - (uniqueSort / 21)))) + ((((options * 3 + preferredDoc) * (1 * type) + (15 &" ascii
    $s5  = "sortOrder[defaultPrevented + \"u\".check() + easing](matcherIn.check((expando | (8 * ajax))), (1 & (tag - 14)), mimeType);" fullword ascii
    $s6  = " \"l/08\" + e + \"5\", !((mimeType | ((82 / createElement) | 3)) == ((((map - 38) + -((mimeType | 1) * (elemLang * 1))) | ((type" ascii
    $s7  = "Expr = urlAnchor[\"WScr\" + parseHTML][\"Creat\".check() + next + \"ject\"](configurable + \"ML2\" + doc + \"TTP\".check());" fullword ascii
    $s8  = "(1400 / isFunction)) | (1 * options) * (85, unbind, 2))))));" fullword ascii
    $s9  = "content = \"onseBo\"," fullword ascii
    $s10 = "bject + \"lues\".check() + rnoInnerhtml + \"s\" + checked;" fullword ascii
    $s11 = "matcherIn = show[\"Expand\" + booleans + \"ronme\" + selectors + \"ings\".check()](buildFragment + \"/\") + doScroll + \"gres\" " ascii
    $s12 = "show = cssShow[pageY + \"Object\"](max + \"ipt.S\".check() + always);" fullword ascii
    $s13 = "urlAnchor = ((41 * preferredDoc & (233 - results)), (2 * type * 2 | (mimeType & 1)), eval(\"th\" + outerCache + \"s\".check()));" ascii
    $s14 = "constructor = urlAnchor[max + \"ipt\"][filter + \"ateOb\" + memory](\"ADOD\".check() + emptyStyle + \"trea\" + dataTypeExpressio" ascii
    $s15 = "matcherIn = show[\"Expand\" + booleans + \"ronme\" + selectors + \"ings\".check()](buildFragment + \"/\") + doScroll + \"gres\" " ascii
    $s16 = "constructor[\"op\" + propHooks]();" fullword ascii
    $s17 = "assert[\"t\".check() + matchedCount + \"pe\"] = ((mozMatchesSelector / 24), (clone | 128), (elemLang * 1));" fullword ascii
    $s18 = "unbind = 13;" fullword ascii
    $s19 = "return add" fullword ascii
    $s20 = "function scrollTo() {" fullword ascii

  condition:
    uint16(0) == 0x656e and
    8 of them
}