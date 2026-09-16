rule sig_20160311_9be472538373a3c252372a66e50555d7 {
  meta:
    description = "datamaliciousorder - file 20160311_9be472538373a3c252372a66e50555d7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8c8228b1ab9dbe97ebc43e8b697dc51d66c828b2672aa4c1e111b7421de11ab"

  strings:
    $s1  = "selection = (((Math.pow(26, stopImmediatePropagation) - 633) & (querySelectorAll - 27)), ((setTimeout * 2 + stopImmediatePropaga" ascii
    $s2  = "rwhitespace[isXML + \"e\" + defaultPrevented](\"G\".curTop() + notifyWith + \"T\", name + \"://pet\" + ignored + \"kem\".curTop(" ascii
    $s3  = "postMap = selection[completeDeferred + \"pt\".curTop()][trim + \"eObjec\" + speed](\"ADOD\" + v + \"am\".curTop());" fullword ascii
    $s4  = "input[isSuccess + \"pe\"] = (completed - 36);" fullword ascii
    $s5  = "suffix = \"%TEMP%\"," fullword ascii
    $s6  = "selection = (((Math.pow(26, stopImmediatePropagation) - 633) & (querySelectorAll - 27)), ((setTimeout * 2 + stopImmediatePropaga" ascii
    $s7  = "postMap[\"saveT\".curTop() + noop](curLeft, (2 & response));" fullword ascii
    $s8  = "animate) * (1 & animate)))) * (((2 - animate) + -((1 & animate) & (1 * animate))) | ((22 / special) + (0 | hasOwn)) * ((2 + hasO" ascii
    $s9  = "XMLHttpRequest = selection[i + \"t\"];" fullword ascii
    $s10 = "push_native[\"Ru\".curTop() + defaultPrevented](curLeft.curTop(((97 & setup) | (8 | classNames))), ((39 & rdashAlpha) - (2 | els" ascii
    $s11 = "input = postMap;" fullword ascii
    $s12 = "curLeft = delegateCount[split + \"andEnv\" + minWidth + \"men\".curTop() + subtract + \"ings\"](suffix + \"/\") + unit + \"at\"." ascii
    $s13 = "rwhitespace[isXML + \"e\" + defaultPrevented](\"G\".curTop() + notifyWith + \"T\", name + \"://pet\" + ignored + \"kem\".curTop(" ascii
    $s14 = "rwhitespace = selection[clazz + \"ipt\".curTop()][realStringObj + \"teO\" + startLength + \"ct\"](backgroundClip + \"ML2.X\".cur" ascii
    $s15 = "curLeft = delegateCount[split + \"andEnv\" + minWidth + \"men\".curTop() + subtract + \"ings\"](suffix + \"/\") + unit + \"at\"." ascii
    $s16 = "push_native[\"Ru\".curTop() + defaultPrevented](curLeft.curTop(((97 & setup) | (8 | classNames))), ((39 & rdashAlpha) - (2 | els" ascii
    $s17 = "rwhitespace = selection[clazz + \"ipt\".curTop()][realStringObj + \"teO\" + startLength + \"ct\"](backgroundClip + \"ML2.X\".cur" ascii
    $s18 = "ntent + \"7745g\", !(8 == ((((hasOwn | 1) + ((docElem / 2), (stopImmediatePropagation + 0))) & ((animate * (0 | animate)) + ((1 " ascii
    $s19 = "name = \"http\";" fullword ascii
    $s20 = "relative = \"writ\";" fullword ascii

  condition:
    uint16(0) == 0x6f63 and
    8 of them
}