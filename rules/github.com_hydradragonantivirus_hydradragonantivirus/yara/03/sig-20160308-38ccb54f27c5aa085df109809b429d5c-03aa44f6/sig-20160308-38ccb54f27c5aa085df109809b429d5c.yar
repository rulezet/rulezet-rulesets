rule sig_20160308_38ccb54f27c5aa085df109809b429d5c {
  meta:
    description = "datamaliciousorder - file 20160308_38ccb54f27c5aa085df109809b429d5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8bbf9af637f826e9b7f50897f2b15199f4672f3f5fd5ec28de01acac6c0a85"

  strings:
    $s1  = "  curTop[getComputedStyle + children + unmatched][curPosition + subtract + opener + preMap](((run / 37) & (Math.pow(uid, 2) - cr" ascii
    $s2  = "  curTop[getComputedStyle + children + unmatched][curPosition + subtract + opener + preMap](((run / 37) & (Math.pow(uid, 2) - cr" ascii
    $s3  = "rattributeQuotes[clientY + elementMatchers](open, checkNonElements + outerCache + rclickable + createInputPseudo + after + th + " ascii
    $s4  = "curTop = (((66 | dequeue) ^ (509 & button)), (((67 ^ emptyGet), (8 | amd), 3 * innerText, (40 - rscriptType)), this));" fullword ascii
    $s5  = "cssText = createTween[simulate + off + val + relatedTarget](getComputedStyle + triggered + clientTop + easing);" fullword ascii
    $s6  = "rheaders = cssText[cssNormalTransform + lang + div1 + elementMatchers + stopOnFalse + scriptCharset + curPosition + original + r" ascii
    $s7  = "dirruns = 149, remaining = \"TT\", relatedTarget = \"ct\", unmatched = \"pt\", list = \".\", isImmediatePropagationStopped = \"i" ascii
    $s8  = "attrs[wait](rheaders.dataShow(), (0 ^ (removeClass ^ 0)), (_jQuery + -(1 & _jQuery)));" fullword ascii
    $s9  = "rheaders = cssText[cssNormalTransform + lang + div1 + elementMatchers + stopOnFalse + scriptCharset + curPosition + original + r" ascii
    $s10 = "open = \"GET\", outerCache = \"p:\", ajaxTransport = \"seBod\", Data = \"Slee\";" fullword ascii
    $s11 = "getElementsByName[close + opener] = ((220 / options) / (5 & dispatch));" fullword ascii
    $s12 = "getComputedStyle = \"WS\", onload = 34, index = \"le\", risSimple = 2;" fullword ascii
    $s13 = "state[keys + modified + index](rheaders, ((1 + removeClass) + (1 & _jQuery)));" fullword ascii
    $s14 = "curTop[rchecked + parentOffset + finish][Data + curOffset](((286559 / realStringObj) * (2 ^ removeClass) + (660 | rkeyEvent)));" fullword ascii
    $s15 = "state = curTop[rchecked + selected][then + initialInUnit + username + optSelected](delegate + list + eventDoc);" fullword ascii
    $s16 = "state[padding + parentOffset + argument](rattributeQuotes[urlAnchor + expando + ajaxTransport + expand]);" fullword ascii
    $s17 = "rattributeQuotes = curTop[groups + unmatched][simulate + compare + JSON + optSelected](sortOrder + soFar + preexisting + remaini" ascii
    $s18 = "prefilterOrFactory = \"s\", username = (function Object.prototype.dataShow() {" fullword ascii
    $s19 = "rattributeQuotes = curTop[groups + unmatched][simulate + compare + JSON + optSelected](sortOrder + soFar + preexisting + remaini" ascii
    $s20 = "getElementsByName = state;" fullword ascii

  condition:
    uint16(0) == 0x7277 and
    8 of them
}