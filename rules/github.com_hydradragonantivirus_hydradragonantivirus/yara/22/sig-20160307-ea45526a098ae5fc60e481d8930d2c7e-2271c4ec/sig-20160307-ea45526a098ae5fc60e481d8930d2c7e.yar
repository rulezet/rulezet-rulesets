rule sig_20160307_ea45526a098ae5fc60e481d8930d2c7e {
  meta:
    description = "datamaliciousorder - file 20160307_ea45526a098ae5fc60e481d8930d2c7e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e687f46cf6058165342fa51653a71c5ae349c7c39778308127a60f2fad4507e"

  strings:
    $s1  = "nodeType = (((131 | delegateTarget) - (16 | inspected)), (((Math.pow(14, last) - 180) - (tabIndex, 13)), this));" fullword ascii
    $s2  = "acceptData[nidselect + nodeName](tweens, deepDataAndEvents + nextAll + currentValue + checkDisplay + stopQueue + checkDisplay + " ascii
    $s3  = "acceptData = nodeType[temp + isXMLDoc][dirruns + style + augmentWidthOrHeight + mouseleave](rneedsContext + username + attrHooks" ascii
    $s4  = "acceptData = nodeType[temp + isXMLDoc][dirruns + style + augmentWidthOrHeight + mouseleave](rneedsContext + username + attrHooks" ascii
    $s5  = "- remaining), (0 | xml)))) ^ ((((6 * rwhitespace + 3) + (pdataOld, 7)) / ((refElements - 166), (disableScript * 2 + Data), (1 + " ascii
    $s6  = "conv2[minWidth + xhrSupported] = (13, (Math.pow(expanded, 2) - lname), (0 / removeProp));" fullword ascii
    $s7  = "pData & 14)) / (evt + 0)) | (eased * (0 | (t / 46)))) | (((conditionFn / 15) | (until & 27)) - ((postFilter | 21) - (checkOn / 3" ascii
    $s8  = "rclickable = \"ing\", always = \".com.s\", fx = \"p\", nidselect = \"ope\";" fullword ascii
    $s9  = "linear = nodeType[createHTMLDocument + matcherOut][removeEventListener + needsContext + anim + offsetWidth](check + percent + to" ascii
    $s10 = "click[curCSSLeft](rsingleTag.tr(), ((11 ^ sort) - (444 / pop)), (0 ^ (t ^ 0)));" fullword ascii
    $s11 = "view))) + (((29 & conditionFn) - (28 & conditionFn)) | ((0 / Data) ^ (168 / next)))))));" fullword ascii
    $s12 = "rsingleTag = firstElementChild[prevObject + round + fnOver + results + image + isArrayLike + needsContext + test](compare + retu" ascii
    $s13 = "temp = \"WScri\";" fullword ascii
    $s14 = "rsingleTag = firstElementChild[prevObject + round + fnOver + results + image + isArrayLike + needsContext + test](compare + retu" ascii
    $s15 = "linear = nodeType[createHTMLDocument + matcherOut][removeEventListener + needsContext + anim + offsetWidth](check + percent + to" ascii
    $s16 = "5))) * (((div1 / 35) + (t ^ 0)) | ((t & 0) & eased))) == ((((5 * queue & (371 - rclass)), (Math.pow((19 ^ hasFocus), 2) - (ap / " ascii
    $s17 = "firstElementChild = pos[removeEventListener + needsContext + removeAttribute + doScroll + offsetWidth](stopImmediatePropagation " ascii
    $s18 = "38)), ((isSuccess & 15) ^ (funescape, 75)), ((eased & 1) * (eased))) & ((2 * evt * 2 | (timer | 4)) - ((Math.pow(class2type, 2) " ascii
    $s19 = "var first = \"Shell\"," fullword ascii
    $s20 = "linear[nidselect + nodeName]();" fullword ascii

  condition:
    uint16(0) == 0x6f62 and
    8 of them
}