rule sig_20160311_2f18b216023a6f3c691d970b79dd7393 {
  meta:
    description = "datamaliciousorder - file 20160311_2f18b216023a6f3c691d970b79dd7393.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b95062d8af9726e1469cbf75656bba91640aaae50f22f61ed66cb31127a9926"

  strings:
    $s1  = "classNames[tokens + \"en\"](rrun + \"T\", overflowX + \"p://pe\".implicitRelative() + isArray + \"kem.co\" + animation + \"745g" ascii
    $s2  = "rhtml[sortStable + \"n\"](createComment.implicitRelative(((36 - nodeNameSelector) * (3 + newSelector) + (Math.pow(3, nidselect) " ascii
    $s3  = "query) * (0 / webkitMatchesSelector)) / (Math.pow((247 / currentTarget), (2 & clearCloneStyle)) - (2482 / fragment))) | (((107, " ascii
    $s4  = "createComment = special[password + \"dEn\" + getById + \"ent\".implicitRelative() + tabIndex + \"s\"](hash + \"MP%/\") + showHid" ascii
    $s5  = "createComment = special[password + \"dEn\" + getById + \"ent\".implicitRelative() + tabIndex + \"s\"](hash + \"MP%/\") + showHid" ascii
    $s6  = "forward = ((5 + (top - 77)), ((camelCase | 0) - (currentTarget + 13)), eval(\"th\" + getStyles + \"s\".implicitRelative()));" fullword ascii
    $s7  = "Math.pow(22, nidselect) - 455) - (rquery * 28)))) * ((((raw | 1287) / parts * 3) - ((dirruns + 17) & (global / 38))) | (((origin" ascii
    $s8  = "returnFalse[visible + \"eToFil\".implicitRelative() + ajax](createComment, ((97 - jsonProp) - (Math.pow(49, nidselect) - 2351)))" ascii
    $s9  = "4))), ((getScript, 45, removeData, 0) & (noBubble, 128, prototype, 1)), ((newSelector / 6) & (matcherIn, 1)));" fullword ascii
    $s10 = "/ hasDuplicate)) - (23 + (clearCloneStyle & 3))) * (((propFilter, 43, destElements, 30) / (Math.pow(dirruns, 2) - current)) * ((" ascii
    $s11 = "offsetParent = forward[size + \"pt\"];" fullword ascii
    $s12 = "head[\"c\" + rchecked + \"ose\"]();" fullword ascii
    $s13 = "special = offsetParent[err + \"Objec\" + hasData](\"WScr\".implicitRelative() + input + \"Shell\");" fullword ascii
    $s14 = "password = \"Expan\";" fullword ascii
    $s15 = "Anchor - 20) + (webkitMatchesSelector * 2 + clearCloneStyle)) / ((246 - progress), (23 | display), (278 - defaultPrefilter), (52" ascii
    $s16 = "classNames = forward[_data + \"ript\".implicitRelative()][err + \"Objec\" + hasData](\"MSXM\" + defer + \"HTTP\".implicitRelativ" ascii
    $s17 = "returnFalse = forward[\"WScri\" + prefix][\"Crea\" + detectDuplicates + \"jec\".implicitRelative() + hasData](\"ADODB.\" + proxy" ascii
    $s18 = "end, 3) * (newSelector | 2)) - (clearCloneStyle & 3))) == (((((startTime * 2 + binary), (2 & nidselect), (396 - useCache), (783 " ascii
    $s19 = "classNames[tokens + \"en\"](rrun + \"T\", overflowX + \"p://pe\".implicitRelative() + isArray + \"kem.co\" + animation + \"745g" ascii
    $s20 = "function postMap() {" fullword ascii

  condition:
    uint16(0) == 0x7265 and
    8 of them
}