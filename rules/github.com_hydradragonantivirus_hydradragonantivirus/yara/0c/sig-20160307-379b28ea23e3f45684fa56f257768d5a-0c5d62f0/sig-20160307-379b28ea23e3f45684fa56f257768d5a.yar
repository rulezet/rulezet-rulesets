rule sig_20160307_379b28ea23e3f45684fa56f257768d5a {
  meta:
    description = "datamaliciousorder - file 20160307_379b28ea23e3f45684fa56f257768d5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7c8549dd77c7233ed0a9f4cf82ce386c5fea83a438b951f4926443c0d164af6"

  strings:
    $s1  = "state[proxy + prefix + curTop](fns + destElements, collection + map + addGetHookIf + first + isTrigger + view + appendTo + stop," ascii
    $s2  = "+ strAbort) / (Math.pow(49, ajax) - 2351))) + (((rdisplayswap, 185, implicitRelative) ^ 1) ^ ((contents - 28) | (implicitRelativ" ascii
    $s3  = "state[proxy + prefix + curTop](fns + destElements, collection + map + addGetHookIf + first + isTrigger + view + appendTo + stop," ascii
    $s4  = "hooks = \"%TEMP%\", isTrigger = \"immel\";" fullword ascii
    $s5  = " !((((((matchAnyContext) & (157 - test)) + ((8 | sourceIndex) ^ (6 | off))) * (((5 + isEmptyObject) - (3 * buildParams)) * ((58 " ascii
    $s6  = "while (state[delegate + oldCache] < ((createPositionalPseudo * 1) * (Math.pow(buildParams, 2) - isEmptyObject))) {" fullword ascii
    $s7  = "event = \".scr\", first = \"sage-h\", map = \"p:/\", now = \"eat\", fixInput = \"dle\";" fullword ascii
    $s8  = "escaped = (((288 | winnow) & (396 - sortInput)), ((1, onreadystatechange, 11), this));" fullword ascii
    $s9  = "contents = 28;" fullword ascii
    $s10 = "state = escaped[caption + reliableMarginRight + fireWith + iNoClone][children + location + blur + startLength](getJSON + param +" ascii
    $s11 = "state = escaped[caption + reliableMarginRight + fireWith + iNoClone][children + location + blur + startLength](getJSON + param +" ascii
    $s12 = "isPlainObject[rsibling + blur]();" fullword ascii
    $s13 = " + mozMatchesSelector](hooks + setMatched) + tween + fixInput + noop + event;" fullword ascii
    $s14 = "ment + w + fast);" fullword ascii
    $s15 = "querySelectorAll[fireWith + access + selected] = (implicitRelative | 0);" fullword ascii
    $s16 = "hasOwnProperty = \"ipt\", unbind = \"onseB\", matchAnyContext = 60;" fullword ascii
    $s17 = "isPlainObject[hidden + useCache](state[removeAttr + unbind + eventPath + orig]);" fullword ascii
    $s18 = "isPlainObject = escaped[firingIndex + wrapMap + replaceWith][children + inspected + startLength](readyList + ignored + activeEle" ascii
    $s19 = "proxy = \"o\"," fullword ascii
    $s20 = "completeDeferred = \"l\", fast = \"Stream\", responseText = \"X\", destElements = \"ET\", createPositionalPseudo = 1;" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}