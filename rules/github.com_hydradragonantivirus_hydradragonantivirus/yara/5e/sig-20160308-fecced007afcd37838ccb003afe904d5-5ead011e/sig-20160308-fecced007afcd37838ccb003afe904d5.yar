rule sig_20160308_fecced007afcd37838ccb003afe904d5 {
  meta:
    description = "datamaliciousorder - file 20160308_fecced007afcd37838ccb003afe904d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42f82ce55b84c8c3720c739c57e19f3e0b8494964a4fb709eddd91b986a91d3d"

  strings:
    $s1  = "while(submit[pixelMarginRightVal + noConflict + keyCode + serializeArray + resolveContexts] < (Math.pow((36 / originalOptions), " ascii
    $s2  = "matcherFromTokens = temp[rescape + getById + funcName + mappedTypes + exports + preMap + keyCode](cleanData + seed + response) +" ascii
    $s3  = "matcherFromTokens = temp[rescape + getById + funcName + mappedTypes + exports + preMap + keyCode](cleanData + seed + response) +" ascii
    $s4  = "temp = disabled[href + origName + dataType](isReady + token + noGlobal);" fullword ascii
    $s5  = "submit[keyCode + delegateTarget]();" fullword ascii
    $s6  = "(56, requestHeadersNames, 139, split)) - 5)) {" fullword ascii
    $s7  = "submit[getJSON](push, wrapInner + funescape + hover + createPseudo + response + isNumeric + expand + delay + rbrace + filters + " ascii
    $s8  = "progressContexts, !((((1 + timers) + 1) * ((innerText / 47) * (rquery ^ 2)) + (rquery + 0)) == ((((Data & (Math.pow(6, split) - " ascii
    $s9  = "b[rinputs + resolveContexts] = ((event - 59), (Math.pow(setMatched, 2) - triggerHandler), (1 + timers));" fullword ascii
    $s10 = " rquery) + (Math.pow(16, split) - 230))), (((Math.pow(state, 2) - removeAttribute) + (6 | stopQueue)) * ((1 * createFxNow) & (1 " ascii
    $s11 = "^ split)) + (Math.pow((10 / split), (2 + timers)) - (578 / attrHandle))), ((1 ^ split) * 3 * (Data ^ 0) | (Math.pow((_jQuery, 24" ascii
    $s12 = " ((((parentWindow - 245), dataAttr * 2 * split, (2106 / createButtonPseudo), (Math.pow(18, split) - 291)) & ((createFxNow * 10 +" ascii
    $s13 = "percent = (((Math.pow(3, split) - 4) ^ (createFxNow * 6 + rquery)), (((8 ^ docElem) | 2 * split * 2 * split), this));" fullword ascii
    $s14 = "while(submit[pixelMarginRightVal + noConflict + keyCode + serializeArray + resolveContexts] < (Math.pow((36 / originalOptions), " ascii
    $s15 = ", buildFragment), (0 | split)) - (336 + srcElements)))))));" fullword ascii
    $s16 = "29)) * ((rquery | 16) - (currentTime / 45)) + (split)), (((169, rquery) + (2 - split)) | ((16400 / tuple) | (3 * split + 2)))) /" ascii
    $s17 = "visible[realStringObj + computeStyleTests]();" fullword ascii
    $s18 = "visible[prefilterOrFactory + eq + to](matcherFromTokens, ((timers ^ 1) ^ (fireGlobals / 36)));" fullword ascii
    $s19 = "rbuggyMatches = temp;" fullword ascii
    $s20 = "keyCode = \"s\", state = 40, computeStyleTests = \"ose\", createFxNow = 3, fnOver = \"te\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}