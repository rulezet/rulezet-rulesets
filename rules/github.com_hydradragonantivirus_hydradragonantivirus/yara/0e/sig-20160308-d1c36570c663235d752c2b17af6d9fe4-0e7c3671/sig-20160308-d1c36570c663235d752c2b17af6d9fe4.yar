rule sig_20160308_d1c36570c663235d752c2b17af6d9fe4 {
  meta:
    description = "datamaliciousorder - file 20160308_d1c36570c663235d752c2b17af6d9fe4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8081bae3a3336dd3e971592241e51dd099d8e7fe357fea75dc4f726b3cfab393"

  strings:
    $s1  = "* 2 + nodeType)), (Math.pow((30 + view), 2) - (crossDomain + 677)), ((dataAndEvents | 20) | (camelKey & 188)), ((Math.pow(getCom" ascii
    $s2  = "to[rcleanScript + duplicates][option + round + marginLeft]((Math.pow((dataAndEvents + 82), (iframe, 113, view)) - (129 | host)))" ascii
    $s3  = "to[rcleanScript + duplicates][option + round + marginLeft]((Math.pow((dataAndEvents + 82), (iframe, 113, view)) - (129 | host)))" ascii
    $s4  = "cache[ajaxTransport](innerText, a + marginLeft + after + matchContext + mouseHooks + classes + guid + stopImmediatePropagation +" ascii
    $s5  = "textContent = events[seekingTransport + unwrap + isBorderBox + getElementsByTagName + mappedTypes + checkDisplay + unwrap](el + " ascii
    $s6  = "& (13 / pattern)))) + (((2 ^ getComputedStyle) + (99 - outermostContext)), (2 & nodeType)))));" fullword ascii
    $s7  = "te + triggered + fadeToggle + currentTarget);" fullword ascii
    $s8  = "params = 595, currentTarget = \"HTTP\", matchContext = \"inis\", winnow = \"ion\", values = 14;" fullword ascii
    $s9  = "cache = to[msFullscreenElement + boxSizingReliable + valueParts + unwrap][getter + matchExpr + configurable + unwrap](getAttribu" ascii
    $s10 = "textContent = events[seekingTransport + unwrap + isBorderBox + getElementsByTagName + mappedTypes + checkDisplay + unwrap](el + " ascii
    $s11 = "delegateType = textContent[async + rsubmittable + _evalUrl + uniqueSort + tag + querySelectorAll + matcherFromGroupMatchers + gu" ascii
    $s12 = "state = to[msFullscreenElement + rnative][seed + addEventListener + copy + selector + unwrap](emptyGet + animation + tr + tag);" fullword ascii
    $s13 = " 2) * (Math.pow(nodeType, 2) - jqXHR) / ((92 - sort) - (138 - margin))), ((Math.pow((Math.pow(13, view) - 152), view) - (33 ^ bo" ascii
    $s14 = "to = (((Math.pow(15, view) - 205) | (nodeType + 125)), ((view | 2), this));" fullword ascii
    $s15 = "to[fnOver + unwrap][option + converters + _default](2 * (lname - 17) * view * 3 * (nodeType ^ 6) * submit * (2 | view) * (1 * su" ascii
    $s16 = "putedStyle, 2) - gotoEnd) / (10 / view))) + (((288 - jsonp), (50 ^ jqXHR)) / (19 + (jqXHR * 2)))), ((((nextSibling / 13) | newDe" ascii
    $s17 = "to[fnOver + unwrap][option + converters + _default](2 * (lname - 17) * view * 3 * (nodeType ^ 6) * submit * (2 | view) * (1 * su" ascii
    $s18 = "cache = to[msFullscreenElement + boxSizingReliable + valueParts + unwrap][getter + matchExpr + configurable + unwrap](getAttribu" ascii
    $s19 = ") * (1 ^ nodeType))) - (((61 & propName) & (11 + currentValue)) - (2 ^ dataAndEvents) * (0 | view) * 2 * (newDefer | 2) * (view)" ascii
    $s20 = "rmultiDash[backgroundClip + winnow] = ((174, trim, 155), (defaultValue - 84), (dataShow | 42), newDefer);" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    8 of them
}