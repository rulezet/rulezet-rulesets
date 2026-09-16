rule sig_20160325_114dfa25f5c2d0ef5579a5bf69f27838 {
  meta:
    description = "datamaliciousorder - file 20160325_114dfa25f5c2d0ef5579a5bf69f27838.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fbe2050c3f6c6b671bc00e57519df41c60a18fdab73f1d81d95721094f4667e"

  strings:
    $s1  = "temp[max + \"p\"]((iNoClone - 54) * (win - 5) * (siblingCheck - 11) * (arr * 5) * (toArray - 19) * (parseFromString + 0) * (rcom" ascii
    $s2  = "temp[max + \"p\"]((iNoClone - 54) * (win - 5) * (siblingCheck - 11) * (arr * 5) * (toArray - 19) * (parseFromString + 0) * (rcom" ascii
    $s3  = "content = \"n.com/\";" fullword ascii
    $s4  = "temp = container[\"WScri\" + indirect];" fullword ascii
    $s5  = "siblingCheck = 13, newContext = \"%TEMP%\", promise = \"ateObj\";" fullword ascii
    $s6  = "isTrigger = temp[\"Cre\" + promise + \"ect\"](s + \"ipt.S\" + finalText);" fullword ascii
    $s7  = "getPropertyValue = isTrigger[\"Expand\" + hide + \"nmentS\" + fnOut + \"s\"](newContext + \"/\") + postFinder + \"Pref\" + origi" ascii
    $s8  = "getPropertyValue = isTrigger[\"Expand\" + hide + \"nmentS\" + fnOut + \"s\"](newContext + \"/\") + postFinder + \"Pref\" + origi" ascii
    $s9  = "function rtagName(swing, getElementsByTagName, rbuggyQSA, matcherFromTokens) {" fullword ascii
    $s10 = "eval(reverse(\"tokenize%5B%22op%22%20+%20els%5D%28%22G%22%20+%20rchecked%20+%20%22T%22%2C%20tween%20+%20%22p%3A//%22%20+%20simpl" ascii
    $s11 = "eval(reverse(\"holdReady%5B%22Ru%22%20+%20attaches%5D%28getPropertyValue%29%3B\"));" fullword ascii
    $s12 = "rneedsContext(url, content, elementMatchers, rcomma, serialize);" fullword ascii
    $s13 = "rcheckableType(returnTrue, postFinder, includeWidth, elementMatchers, fail);" fullword ascii
    $s14 = "function thead() {" fullword ascii
    $s15 = "eval(reverse(\"rtagName%28%22Respon%22%20+%20getAttribute%20+%20%22dy%22%2C%20%28%28preMap%7C2%29%7C%28preMap%7C15%29%29%2C%20se" ascii
    $s16 = "win = 10, special = \".ex\", throws = \"eXObje\", getAttribute = \"seBo\";" fullword ascii
    $s17 = "thead(assert, getAttribute);" fullword ascii
    $s18 = "eval(reverse(\"onreadystatechange%28getPropertyValue%2C%20camelCase%2C%20%28%28needsContext%2C39%2Cconv%2C2%29+%28inPage%260%29%" ascii
    $s19 = "\".\" + last + \"c\" + url;" fullword ascii
    $s20 = "eval(reverse(\"onreadystatechange%28getPropertyValue%2C%20camelCase%2C%20%28%28needsContext%2C39%2Cconv%2C2%29+%28inPage%260%29%" ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}