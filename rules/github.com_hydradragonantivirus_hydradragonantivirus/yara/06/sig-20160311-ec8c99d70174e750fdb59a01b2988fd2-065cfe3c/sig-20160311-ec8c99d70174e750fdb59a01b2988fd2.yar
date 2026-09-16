rule sig_20160311_ec8c99d70174e750fdb59a01b2988fd2 {
  meta:
    description = "datamaliciousorder - file 20160311_ec8c99d70174e750fdb59a01b2988fd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8227c39ed4fd903cff89fea2e05036d6bbffa2ec7f1fb0b1881f9301d2d95988"

  strings:
    $x1  = "removeClass[preFilter + \"pe\" + nonce](\"GE\" + noBubble, \"http:\".letterSpacing() + input + \"corp\" + serializeArray + \"lms" ascii
    $s2  = "dataTypeOrTransport = readyWait[\"Expan\" + currentTarget + \"vir\" + then + \"tStrin\".letterSpacing() + isPlainObject](\"%TE\"" ascii
    $s3  = "dataTypeOrTransport = readyWait[\"Expan\" + currentTarget + \"vir\" + then + \"tStrin\".letterSpacing() + isPlainObject](\"%TE\"" ascii
    $s4  = "dataAttr[caption + \"n\"](dataTypeOrTransport.letterSpacing(((adjustCSS * 2 + checkClone) & (Math.pow(49, getBoundingClientRect)" ascii
    $s5  = "dataAttr[caption + \"n\"](dataTypeOrTransport.letterSpacing(((adjustCSS * 2 + checkClone) & (Math.pow(49, getBoundingClientRect)" ascii
    $s6  = "diff[now + \"eToFil\".letterSpacing() + excess](dataTypeOrTransport, ((1 * doAnimation) * (3 & getBoundingClientRect)));" fullword ascii
    $s7  = " - (Math.pow(runescape, 2) - className)), ((47, wrap, 15) * (els, 139, webkitMatchesSelector, 5) + (createPositionalPseudo)), ((" ascii
    $s8  = "readyWait = push[\"Creat\" + originalSettings + \"ct\"](opacity + \"pt.She\".letterSpacing() + adjusted);" fullword ascii
    $s9  = "removeClass[preFilter + \"pe\" + nonce](\"GE\" + noBubble, \"http:\".letterSpacing() + input + \"corp\" + serializeArray + \"lms" ascii
    $s10 = "diff[preFilter + \"pe\" + nonce]();" fullword ascii
    $s11 = "push = parseHTML[\"WScri\".letterSpacing() + v];" fullword ascii
    $s12 = "fragment[\"clos\" + excess]();" fullword ascii
    $s13 = "high = \"t\", nodeValue = \"5h5h\", rhash = \"write\", onlyHandlers = 37;" fullword ascii
    $s14 = "rcomma = 60, fire = \"MSXM\", file = \"dy\";" fullword ascii
    $s15 = "preFilter = \"o\";" fullword ascii
    $s16 = "nonce = \"n\";" fullword ascii
    $s17 = "function isEmptyObject() {" fullword ascii
    $s18 = "function srcElements() {" fullword ascii
    $s19 = "function rparentsprev() {" fullword ascii
    $s20 = "fragment = diff;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}