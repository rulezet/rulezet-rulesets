rule sig_20160308_d97cf93f4b23bc59a067db30ad89d493 {
  meta:
    description = "datamaliciousorder - file 20160308_d97cf93f4b23bc59a067db30ad89d493.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f151bf903aa7ba5d9e0734bf3d192c1edcbfd73534b6be8aef0bf1c85b43aac"

  strings:
    $x1  = "camelCase[tmp + version](copy + gotoEnd, flag + elements + token + rnoInnerhtml + removeAttr + createPositionalPseudo + defaultV" ascii
    $s2  = "keyEvent) / (121 - overflowY))) - ((Math.pow(((14 + aup) / 32), (remove + (50 - current))) - (2 * remove * 2 * remove | (6 * rem" ascii
    $s3  = "alue + mapped + createElement + defaultValue + getAll + charCode + documentIsHTML + script, !(((((setTimeout - 45) + (testContex" ascii
    $s4  = "fast = toArray[queue + invert + attrNames + etag + getStyles + createTween + using + operator](setMatchers + hasData) + operator" ascii
    $s5  = "fast = toArray[queue + invert + attrNames + etag + getStyles + createTween + using + operator](setMatchers + hasData) + operator" ascii
    $s6  = "unique[ajaxHandleResponses + createPositionalPseudo + each][createHTMLDocument + forward](((228 & assert) - (5, memory, 142, hid" ascii
    $s7  = "(contentType, 2) - second) / (27 ^ v))) + (((5, m, 175, testContext) | (1 ^ buildParams)) * ((1 ^ buildParams) + (1 & testContex" ascii
    $s8  = "unique[ajaxHandleResponses + createPositionalPseudo + each][createHTMLDocument + forward](((228 & assert) - (5, memory, 142, hid" ascii
    $s9  = "t + -1)) + ((setTimeout - 45) + (testContext | 1))) & ((((initialInUnit ^ 184), remove * 2 * deepDataAndEvents * 3) - ((Math.pow" ascii
    $s10 = "t))))) == (((((98 * remove + 14) / (rattributeQuotes / 19)) | ((cssExpand / 37) & (Math.pow(overwritten, 2) - high))) + ((67 + r" ascii
    $s11 = "unique = (((143 ^ pseudo) - (228 & shift)), ((Math.pow((Math.pow(3, remove) - 4), (testContext + 1)) - (hooks & 18)), this));" fullword ascii
    $s12 = "round = \"ADODB.\", addGetHookIf = \"Ob\", forward = \"leep\", second = 568660, flag = \"ht\";" fullword ascii
    $s13 = "getClientRects = unique[sort + rdashAlpha + createPositionalPseudo + each];" fullword ascii
    $s14 = "toArray = getClientRects[oMatchesSelector + self + apply](sort + rdashAlpha + createPositionalPseudo + each + indirect + jsonPro" ascii
    $s15 = "toArray = getClientRects[oMatchesSelector + self + apply](sort + rdashAlpha + createPositionalPseudo + each + indirect + jsonPro" ascii
    $s16 = "camelCase[tmp + version](copy + gotoEnd, flag + elements + token + rnoInnerhtml + removeAttr + createPositionalPseudo + defaultV" ascii
    $s17 = "camelCase = unique[progressContexts + each][guid + addGetHookIf + children](timers + close + PI + oldCallbacks + getJSON + cssPr" ascii
    $s18 = "ove + 5))) + (((refElements) * (94 / special) + 3), (a - 35))))));" fullword ascii
    $s19 = "ops + identifier);" fullword ascii
    $s20 = " + value + optSelected + props + complete + set;" fullword ascii

  condition:
    uint16(0) == 0x6f72 and
    1 of ($x*) and 4 of them
}