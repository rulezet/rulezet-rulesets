rule sig_20160309_1a96941971eb9fcf3bb75cb92c9bac9d {
  meta:
    description = "datamaliciousorder - file 20160309_1a96941971eb9fcf3bb75cb92c9bac9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36f8426d67841d7c78d6ddada4bd85544e70e3362335c372821c1787c14f12ba"

  strings:
    $s1  = "mapped[arg + merge](rcleanScript, valHooks + selector + n + trim + matchContext + tuples + preexisting + types + closest + proto" ascii
    $s2  = "mapped = implementation[delegateTarget + text + restoreScript][createElement + isPlainObject + origName](parseOnly + self + genF" ascii
    $s3  = "mapped = implementation[delegateTarget + text + restoreScript][createElement + isPlainObject + origName](parseOnly + self + genF" ascii
    $s4  = "4 + prevUntil)) | (15 / targets))) * ((((3 & postFilter) ^ (1 + -offsetParent)) & ((192 - writable) / 2 * newContext * 2 * postF" ascii
    $s5  = "swing[delegateType](cors.postDispatch(), ((0 ^ destElements) | (0 ^ destElements)), ((5 - targets) & (2 - offsetParent)));" fullword ascii
    $s6  = " - (Math.pow(6181, postFilter) - 38198462)), ((context, 2) & (postFilter | 3))))));" fullword ascii
    $s7  = "nts)), (Math.pow((32 | ready), (1 ^ newContext)) - (172, curCSSTop, 253, rCRLF)), (Math.pow((77 + newContext), (1 * postFilter))" ascii
    $s8  = "pixelMarginRightVal ^ 15), (stop / 12)) - (rcombinators + 52)), ((ifModified, 203, cur, 1) * (offsetParent * 2))) - ((Math.pow(f" ascii
    $s9  = "cors = xhr[attrNames + opt + responseHeaders + curCSSLeft + condense + dequeue](requestHeaders + now + host + marginRight) + nid" ascii
    $s10 = "+ 0) + -(progressValues / 13)) | ((contains, 0) ^ postFilter))) * (((2 & newContext) ^ (1 + -offsetParent)) & (((40 ^ next) / (2" ascii
    $s11 = "ts)) ^ (94 / animate)) * ((((18 | padding) ^ 7 * assert) - ((13 * oldCallbacks + 9) / (postFinder | 0))) - (Math.pow((Math.pow((" ascii
    $s12 = "implementation = (((1 | camel) - (Math.pow(21, postFilter) - 412)), (((clearTimeout / 5), (msFullscreenElement / 1), (nodeType *" ascii
    $s13 = "implementation = (((1 | camel) - (Math.pow(21, postFilter) - 412)), (((clearTimeout / 5), (msFullscreenElement / 1), (nodeType *" ascii
    $s14 = "cors = xhr[attrNames + opt + responseHeaders + curCSSLeft + condense + dequeue](requestHeaders + now + host + marginRight) + nid" ascii
    $s15 = "mapped[arg + merge](rcleanScript, valHooks + selector + n + trim + matchContext + tuples + preexisting + types + closest + proto" ascii
    $s16 = "preventDefault[contentDocument + cssNormalTransform + merge] = (destElements / 12);" fullword ascii
    $s17 = "type + eventPath + raw + insertBefore + string + slideToggle + sortDetached, !((((pointerleave * 2 * postFilter * 2 * postFilter" ascii
    $s18 = "xhr = noGlobal[defaultPrevented + origName](show + getStyles + isImmediatePropagationStopped + charset);" fullword ascii
    $s19 = "ilter * 2)) & ((offsetParent * (44 - isSuccess)) - ((22 - isArray) - (63 / padding)))) == (((1 & offsetParent) * (1 * destElemen" ascii
    $s20 = "implementation[isXML + hasClass][click + values](((162, allTypes, 20, fixHooks) & (26246 - dirrunsUnique)));" fullword ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}