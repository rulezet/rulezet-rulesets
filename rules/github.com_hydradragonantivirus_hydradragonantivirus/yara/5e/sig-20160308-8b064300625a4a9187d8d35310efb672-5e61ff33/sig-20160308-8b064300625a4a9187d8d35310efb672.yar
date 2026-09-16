rule sig_20160308_8b064300625a4a9187d8d35310efb672 {
  meta:
    description = "datamaliciousorder - file 20160308_8b064300625a4a9187d8d35310efb672.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4857c8a586ecc82d30062ca3be007b448be0d135798d8c7c318e86701d5533ce"

  strings:
    $x1  = "rfxtypes[cssText](requestHeadersNames + grep, proxy + structure + matcherFromTokens + rejectWith + border + lastModified + postF" ascii
    $s2  = "diff = (((408 / unbind) | (5980 / obj)), (((3 | dirrunsUnique) & (Math.pow(14, parts) - 181)), this));" fullword ascii
    $s3  = "rfxtypes[cssText](requestHeadersNames + grep, proxy + structure + matcherFromTokens + rejectWith + border + lastModified + postF" ascii
    $s4  = "diff[pseudos + holdReady + returnFalse][getJSON + adown](((unbind * 4) + (valueParts / 38)));" fullword ascii
    $s5  = "while (rfxtypes[qsaError + unwrap] < ((Math.pow(4, parts) - 11) & (unmatched * 6))) {" fullword ascii
    $s6  = "9 + stopPropagation) - (15 * parts + 5)) * ((success ^ 2) ^ (success | 1)) + ((restoreScript / 10) | (success ^ 0)))) + (((parts" ascii
    $s7  = "contentType[unit + responseFields] = ((0 | unmatched) + -(1 * unmatched));" fullword ascii
    $s8  = "optDisabled[password + curPosition] = ((success | 1) | (propName, 194, unmatched));" fullword ascii
    $s9  = " * 2 + setPositiveNumber)), ((4 ^ unmatched) * 2 * state), ((221 & hash) & (363 - related)), (1 * parts) * (96 / speeds)) & (((1" ascii
    $s10 = " * 2 * setPositiveNumber * 2 * parts - 2 * parts * 5 * unbind) - ((24 | t) - (987 / responseContainer))) & (((2 | cos) / 7 * par" ascii
    $s11 = "diff[dataType + rsingleTag + returnFalse][fire + doScroll](((completed - 6874) - (rbrace | 420)));" fullword ascii
    $s12 = "guid = rhash[div1 + dataUser + href + find + removeEventListener + start + click + tween + pnum](off + matchExpr + rsubmittable)" ascii
    $s13 = "ilter + j + undelegate + timers + selectedIndex + responseHeaders + access, !(setPositiveNumber < (((((7 * parts + 2) | (timerId" ascii
    $s14 = "guid = rhash[div1 + dataUser + href + find + removeEventListener + start + click + tween + pnum](off + matchExpr + rsubmittable)" ascii
    $s15 = "postSelector[animation + write](guid, ((1 * parts) & (0 | parts)));" fullword ascii
    $s16 = "speeds = 48, unmatched = 1, password = \"typ\";" fullword ascii
    $s17 = "rhash = opts[statusCode + pageX + returnFalse + tick + curPosition + dir](rhtml + stopOnFalse + prototype + funcName);" fullword ascii
    $s18 = "context = activeElement + removeEventListener;" fullword ascii
    $s19 = "rfxtypes = diff[rhtml + click + cur][createOptions + hold + curValue + dir](selectors + onerror + documentElement + assert);" fullword ascii
    $s20 = "structure = \"ttp:\"," fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}