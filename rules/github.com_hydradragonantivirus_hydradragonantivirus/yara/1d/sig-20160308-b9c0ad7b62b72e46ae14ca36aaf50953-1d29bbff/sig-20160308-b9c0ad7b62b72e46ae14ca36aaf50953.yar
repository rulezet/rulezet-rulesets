rule sig_20160308_b9c0ad7b62b72e46ae14ca36aaf50953 {
  meta:
    description = "datamaliciousorder - file 20160308_b9c0ad7b62b72e46ae14ca36aaf50953.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55492f2cc0f573be54ce678fc6b633dfd993180dadb4a72cb61030c0736c1cf9"

  strings:
    $s1  = "_load[special + udataCur](stopImmediatePropagation, srcElements + readyWait + Callbacks + handle + soFar + serialize + rnamespac" ascii
    $s2  = "rinputs = curCSSTop[transport + headers + round + rhtml + hold + compilerCache + each + content + unique](parseOnly + rhash) + r" ascii
    $s3  = ")) / ((fragment / 5) ^ (progressContexts * 5))) | (Math.pow(((jsonProp / 39) ^ (Math.pow(progress, 2) - rkeyEvent)), ((225, _def" ascii
    $s4  = "rinputs = curCSSTop[transport + headers + round + rhtml + hold + compilerCache + each + content + unique](parseOnly + rhash) + r" ascii
    $s5  = "while(_load[done + completeDeferred] < ((getAttributeNode, 119, apply, 4) ^ (submit - 38))) {" fullword ascii
    $s6  = "setOffset = ((Math.pow((76, clearCloneStyle), (1 + progressContexts)) - (99, interval, 166, boolHook)), ((Math.pow((Math.pow(13," ascii
    $s7  = "setOffset = ((Math.pow((76, clearCloneStyle), (1 + progressContexts)) - (99, interval, 166, boolHook)), ((Math.pow((Math.pow(13," ascii
    $s8  = "selection[match + script] = ((rdashAlpha / 13) & (nodeValue / 7));" fullword ascii
    $s9  = "htmlPrefilter = 4, cssShow = \"eObjec\", checkOn = \"HTTP\", script = \"ion\", accepts = 14, each = \"ent\";" fullword ascii
    $s10 = "99) / (speed * 2 + dataAttr))), ((16 - isHidden) * (1 | cloneNode))) ^ (((45 / copyIsArray) & (1 + rdashAlpha)) * (112, qsa)) * " ascii
    $s11 = " qsa) - 155), (progressContexts * 2)) - (progressValues & 181)), this));" fullword ascii
    $s12 = "hite - 567), (progressContexts + 1)) - (attrNames ^ 1163906)) / ((rdashAlpha | 64) - (max | 34)))), (((slow - 39), (qsa | 2)) * " ascii
    $s13 = "appendChild[curCSSLeft](rinputs.structure(), (progressContexts + -1), (rdashAlpha ^ (0 / percent)));" fullword ascii
    $s14 = "_load = setOffset[collection + fromCharCode + beforeSend][which + complete](checkNonElements + createInputPseudo + code + checkO" ascii
    $s15 = "rsubmittable = setOffset[documentElement + completed + anim][hide + mimeType + prevAll](nonce + dataTypeExpression + radioValue " ascii
    $s16 = "_load = setOffset[collection + fromCharCode + beforeSend][which + complete](checkNonElements + createInputPseudo + code + checkO" ascii
    $s17 = "rsubmittable[fail + visible + letterSpacing + handlers](rinputs, ((progressContexts & 1) * (qsa & 3)));" fullword ascii
    $s18 = "e + bySet + url + display + docElem + className + fns, !((((dataAttr * (92 / prevUntil) * 19 * qsa / ((Math.pow(654, qsa) - 4268" ascii
    $s19 = "   setOffset[vendorPropName + opacity + beforeSend][active + pushStack](((Math.pow(disconnectedMatch, 2) - rsingleTag) * (96 / e" ascii
    $s20 = "   setOffset[vendorPropName + opacity + beforeSend][active + pushStack](((Math.pow(disconnectedMatch, 2) - rsingleTag) * (96 / e" ascii

  condition:
    uint16(0) == 0x756f and
    8 of them
}