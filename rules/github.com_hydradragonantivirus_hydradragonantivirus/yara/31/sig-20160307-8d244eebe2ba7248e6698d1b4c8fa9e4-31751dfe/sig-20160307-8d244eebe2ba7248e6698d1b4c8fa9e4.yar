rule sig_20160307_8d244eebe2ba7248e6698d1b4c8fa9e4 {
  meta:
    description = "datamaliciousorder - file 20160307_8d244eebe2ba7248e6698d1b4c8fa9e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac9f7a3c2ebe7846ad430dd9482e43500b3959d5e9ee3e1ccc67bd769ea5818d"

  strings:
    $s1  = "responseHeaders = textContent[guaranteedUnique + tweens + bindType + dataShow + base + left + createInputPseudo](conv + stopProp" ascii
    $s2  = "responseHeaders = textContent[guaranteedUnique + tweens + bindType + dataShow + base + left + createInputPseudo](conv + stopProp" ascii
    $s3  = "ajaxSettings = \"%TEMP%\", optSelected = 9, responseType = \"tate\", fixHook = \"r\", get = \".Shel\";" fullword ascii
    $s4  = "fadeToggle = Sizzle[conv + stopPropagation][unit + unwrap + converters + createInputPseudo](requestHeaders + identifier + compar" ascii
    $s5  = "fadeToggle = Sizzle[conv + stopPropagation][unit + unwrap + converters + createInputPseudo](requestHeaders + identifier + compar" ascii
    $s6  = "cos = Sizzle[fragment + events + resolveValues + fixHook + inArray][password + querySelectorAll + dataShow + copy + bindType](fn" ascii
    $s7  = "cos = Sizzle[fragment + events + resolveValues + fixHook + inArray][password + querySelectorAll + dataShow + copy + bindType](fn" ascii
    $s8  = "backgroundClip = responseHeaders[curElem + top + selected + params + sel + hasFocus](ajaxSettings + fn) + bindType + tmp + seeki" ascii
    $s9  = "fadeToggle[simple](charCode, conv2 + finalValue + tabIndex + parseOnly + postSelector + using + parts + ret + inPage, !((((Math." ascii
    $s10 = "* ((37 ^ jsonpCallback) - (Math.pow(21, doc) - 405)), (((combinator + 0) * (rtagName / 30)) + ((mouseleave * 6 + combinator) - (" ascii
    $s11 = " offsetWidth) / (20 ^ msFullscreenElement)) / ((Math.pow(54, doc) - 2850), (speeds / 35)))), (Math.pow(((combinator & 1) * doc) " ascii
    $s12 = "Sizzle[nativeStatusText + bindType][events + emptyGet + dataShow + fxNow](((6 ^ html) * (2 ^ createTween) + (4 * opener + 2)));" fullword ascii
    $s13 = "backgroundClip = responseHeaders[curElem + top + selected + params + sel + hasFocus](ajaxSettings + fn) + bindType + tmp + seeki" ascii
    $s14 = "fadeToggle[simple](charCode, conv2 + finalValue + tabIndex + parseOnly + postSelector + using + parts + ret + inPage, !((((Math." ascii
    $s15 = "cos[off + responseHeadersString](backgroundClip, ((combinator * 2) ^ (combinator * 0)));" fullword ascii
    $s16 = "pow(((11 ^ updateFunc) ^ (567 / optSelected)), (1 * (combinator * 2))) - ((marginLeft & 15100) - (method + 1636)))), (((matchesS" ascii
    $s17 = "resolve[isReady](backgroundClip.pointerleave(), ((combinator * 0) / (visibility, 9, matchIndexes, 23)), (createTween ^ 0));" fullword ascii
    $s18 = "elector & 7) ^ ((mouseleave ^ 12) | (currentValue ^ 6))) ^ (((combinator + 22) + (owner, 63, view, 229)) / (Math.pow((rinputs), " ascii
    $s19 = "textContent = Sizzle[replaceWith + inArray];" fullword ascii
    $s20 = "agation + get + split);" fullword ascii

  condition:
    uint16(0) == 0x7468 and
    8 of them
}