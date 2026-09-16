rule sig_20160308_398d44ee015374251aa8ff91ecd6208c {
  meta:
    description = "datamaliciousorder - file 20160308_398d44ee015374251aa8ff91ecd6208c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9995f56c031457acacfa25938d4abdbaa1ba288d79c1ac3de3371e2255e6c816"

  strings:
    $x1  = "duration = parseHTML[hasContent + hasScripts + fireWith + adown](processData + timers + getPropertyValue + trim + hide + returnF" ascii
    $x2  = "duration = parseHTML[hasContent + hasScripts + fireWith + adown](processData + timers + getPropertyValue + trim + hide + returnF" ascii
    $s3  = "realStringObj[postSelector + elem](_, readyState + sel + getElementById + simple + getAll + dataAttr + defaultPrevented + unwrap" ascii
    $s4  = " + responseHeadersString + updateFunc + sel + hidden + matcherOut + resolveValues, !(((rcleanScript | (((25 - clientLeft) * (80 " ascii
    $s5  = "realStringObj = err[processData + cssExpand][emptyStyle + curPosition + contextBackup + index](rcombinators + prototype + serial" ascii
    $s6  = "realStringObj = err[processData + cssExpand][emptyStyle + curPosition + contextBackup + index](rcombinators + prototype + serial" ascii
    $s7  = "emptyGet[delegateTarget + matchesSelector] = ((queue + -1));" fullword ascii
    $s8  = "/ childNodes) + (115 / pos)) / ((4 - rcleanScript) | (2 ^ queue)))) ^ ((Math.pow(((1 * w) & (2 ^ queue)), ((101 - sourceIndex) -" ascii
    $s9  = " (23 ^ rinputs))) - ((6 & firstDataType) + (0 & queue))) ^ (((1 + rcleanScript) | (1 + -queue)) & ((0 & rcleanScript) ^ (136, r2" ascii
    $s10 = "realStringObj[postSelector + elem](_, readyState + sel + getElementById + simple + getAll + dataAttr + defaultPrevented + unwrap" ascii
    $s11 = "err[host + eventHandle][binary](((1296 | protocol) / (3 * grep + 1)));" fullword ascii
    $s12 = "err[conv2 + isReady][refElements + copy](((removeEvent * 2 + nodeNameSelector) - (14015 & html)));" fullword ascii
    $s13 = "setMatcher = \"%TEMP%\";" fullword ascii
    $s14 = "err = (((Math.pow(104, useCache) - 10637), (Math.pow(rattributeQuotes, 2) - rfocusMorph), (77 * useCache + 45)), (((hash - 10) +" ascii
    $s15 = "err = (((Math.pow(104, useCache) - 10637), (Math.pow(rattributeQuotes, 2) - rfocusMorph), (77 * useCache + 45)), (((hash - 10) +" ascii
    $s16 = "location[contentDocument + calculatePosition + preexisting](defineProperty, ((fcamelCase / 7), (animated - 130), w * 2 * optall," ascii
    $s17 = "location[contentDocument + calculatePosition + preexisting](defineProperty, ((fcamelCase / 7), (animated - 130), w * 2 * optall," ascii
    $s18 = "defineProperty = duration[getStyles + _queueHooks + round + newDefer + has + getJSON](setMatcher + sel) + createDocumentFragment" ascii
    $s19 = "defineProperty = duration[getStyles + _queueHooks + round + newDefer + has + getJSON](setMatcher + sel) + createDocumentFragment" ascii
    $s20 = "parseHTML = err[host + eventHandle];" fullword ascii

  condition:
    uint16(0) == 0x6573 and
    1 of ($x*) and 4 of them
}