rule sig_20160308_b380dbf9269107d9f680d8b76d6694e2 {
  meta:
    description = "datamaliciousorder - file 20160308_b380dbf9269107d9f680d8b76d6694e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f89bb9003edafd84977ff723d93aae7d2a383b162cf1219271d8d047fde0ff1"

  strings:
    $s1  = "while(key[operator + run + responseFields + open] < ((28 - domManip) | (0 | marginDiv))) {" fullword ascii
    $s2  = "_default = compile[opts + clearQueue][rrun + scrollTop + rattributeQuotes](emptyGet + offsetWidth + cloneCopyEvent);" fullword ascii
    $s3  = "compile = (((24 + cssText) | (53 + finalText)), ((Math.pow((Math.pow(6, udataOld) - 28), (marginDiv ^ 2)) - (marginDiv | 53)), t" ascii
    $s4  = "compile = (((24 + cssText) | (53 + finalText)), ((Math.pow((Math.pow(6, udataOld) - 28), (marginDiv ^ 2)) - (marginDiv | 53)), t" ascii
    $s5  = "key = compile[setDocument + whitespace + clearQueue][ready + keys + charset](classCache + temp + complete + eventDoc + stopImmed" ascii
    $s6  = "getComputedStyle = t[timerId + view + removeAttribute + manipulationTarget + unit + nid + setter + _data + scale](setGlobalEval " ascii
    $s7  = "getComputedStyle = t[timerId + view + removeAttribute + manipulationTarget + unit + nid + setter + _data + scale](setGlobalEval " ascii
    $s8  = "key = compile[setDocument + whitespace + clearQueue][ready + keys + charset](classCache + temp + complete + eventDoc + stopImmed" ascii
    $s9  = "_default[ajaxConvert + eventHandle + replaceWith](getComputedStyle, ((check * 3) & (udataOld + 0)));" fullword ascii
    $s10 = ", 249, check))) * (((107 - each) + (Math.pow(22, udataOld) - 449)) / (Math.pow((focusin & 38), (udataOld ^ 0)) - (fireGlobals * " ascii
    $s11 = "3 + _$)))) * ((((10 + udataOld) ^ 5 * now * 2) | ((pseudos - 280) / (createElement / 33))) - (Math.pow((now * 2 + check) * (1 + " ascii
    $s12 = "manipulationTarget = \"nviron\", unit = \"men\";" fullword ascii
    $s13 = "compile[escaped + opt + clearQueue][pixelPosition + split](((118 & specified) & (Math.pow(81, udataOld) - 6458)));" fullword ascii
    $s14 = "key[raw + overflow](concat, nodeNameSelector + charset + charset + global + rquickExpr + createTween + keyHooks + camelCase + fi" ascii
    $s15 = "elements[matcherOut + fx + overflow] = ((bubbleType / 31) - (check & 1));" fullword ascii
    $s16 = "key[head]();" fullword ascii
    $s17 = "udataOld), ((2 & udataOld) + (0 / valueIsBorderBox))) - ((289 | radio) & (640 - hasFocus)))) * ((((20 - isSimulated) * (1 & marg" ascii
    $s18 = "temp = \"XML\";" fullword ascii
    $s19 = "compile[letterSpacing + timeStamp + charset][matchContext](((rnumnonpx & 6391) * (udataOld | 0) + (cur & 2514)));" fullword ascii
    $s20 = "x + xhrSupported + insertAfter + Deferred + parseOnly, !(now < ((((1 & check) ^ (0 | marginDiv)) * ((0 | check) & (245, elemLang" ascii

  condition:
    uint16(0) == 0x7563 and
    8 of them
}