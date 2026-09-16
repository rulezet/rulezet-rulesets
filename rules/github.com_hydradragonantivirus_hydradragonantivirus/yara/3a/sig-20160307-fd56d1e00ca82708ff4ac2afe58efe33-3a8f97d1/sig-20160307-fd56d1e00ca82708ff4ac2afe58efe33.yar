rule sig_20160307_fd56d1e00ca82708ff4ac2afe58efe33 {
  meta:
    description = "datamaliciousorder - file 20160307_fd56d1e00ca82708ff4ac2afe58efe33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f0a44a484a63763c1a294b9b54bf865fdb884080ab72b91c0655b2a33def4c2"

  strings:
    $s1  = "appendChild[attrHandle + curValue](iterator, clazz + arr + rwhitespace + pageY + createPseudo + slideToggle + bup + index + crea" ascii
    $s2  = "opacity[transports + delegateTarget][not](((success & 125) ^ (getStyles - 17)));" fullword ascii
    $s3  = "parent[operator](getAllResponseHeaders.push(), ((elems - 30) * (rquickExpr * 0)), (createTween ^ 0));" fullword ascii
    $s4  = "rcssNum = opacity[lname + classes + mouseleave + uniqueID][textContent + delegateTarget + sortStable + matched](duplicates + rha" ascii
    $s5  = "opacity[completeDeferred + sortOrder + delegateTarget][siblings + settings](((remove, 212, pageYOffset, 7335) + (box * 2 + elem)" ascii
    $s6  = "opacity[completeDeferred + sortOrder + delegateTarget][siblings + settings](((remove, 212, pageYOffset, 7335) + (box * 2 + elem)" ascii
    $s7  = "var postFilter = \"%TEMP%\";" fullword ascii
    $s8  = "))) - ((37 * border + 31) - (getComputedStyle * 2 + marginLeft)))), (((13 + createTween) - (11 & cos)) * (1 + rquickExpr) * (1 *" ascii
    $s9  = " (rquickExpr * 2)) / ((rquickExpr & 1) + (rquickExpr + 0)) * (when ^ (0 / getComputedStyle)))) - (((51 * when + 40), (curLeft | " ascii
    $s10 = "rcssNum = opacity[lname + classes + mouseleave + uniqueID][textContent + delegateTarget + sortStable + matched](duplicates + rha" ascii
    $s11 = "teTextNode + temp, !((Math.pow(((((rnumnonpx, 112, JSON, 0) | (border ^ 18)) | ((unmatched * 3 + addHandle) & (20 | unmatched)))" ascii
    $s12 = "while (appendChild[duration + identifier + finalDataType + rtrim] < (Math.pow(3, border) - (2 * border + 1))) {" fullword ascii
    $s13 = "appendChild = opacity[htmlPrefilter + ridentifier][overrideMimeType + onerror + parseOnly + firstChild + cacheLength + matched](" ascii
    $s14 = " - (Math.pow((Math.pow((Math.pow(5, border) - 18), (rquickExpr * 2)) - (fired, 72, swing)), ((0 | createTween) ^ (3 - rquickExpr" ascii
    $s15 = "opacity = (((Math.pow(27, border) - 681) + when * 11), (((when + 3) * (createTween | 3)), this));" fullword ascii
    $s16 = "appendChild = opacity[htmlPrefilter + ridentifier][overrideMimeType + onerror + parseOnly + firstChild + cacheLength + matched](" ascii
    $s17 = "getStyles = 22, iterator = \"GET\", fragment = \"E\", fixInput = \"op\", contentType = \"oFile\";" fullword ascii
    $s18 = "getAllResponseHeaders = matchExpr[callbackName + sortOrder + firstElementChild + isImmediatePropagationStopped + fragment + raw " ascii
    $s19 = "identifier = \"y\", overrideMimeType = \"C\", unloadHandler = \"Proper\";" fullword ascii
    $s20 = "rcssNum[includeWidth + completed](appendChild[attrs + dataPriv + percent]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}