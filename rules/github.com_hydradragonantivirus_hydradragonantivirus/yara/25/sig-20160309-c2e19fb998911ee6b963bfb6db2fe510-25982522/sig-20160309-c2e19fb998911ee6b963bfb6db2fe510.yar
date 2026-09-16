rule sig_20160309_c2e19fb998911ee6b963bfb6db2fe510 {
  meta:
    description = "datamaliciousorder - file 20160309_c2e19fb998911ee6b963bfb6db2fe510.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "430c7ef83968e9f360421f88a71465a9a85d41c73cc858586c4a032aa62a0be1"

  strings:
    $s1  = "matches[disableScript](tokenize + _removeData, propFilter + hasOwn + fn + deep + _evalUrl + hooks + fnOver + attr + appendTo + a" ascii
    $s2  = "speed = innerText[xml + lname + nativeStatusText + origName + exports](relatedTarget + responseContainer + proxy);" fullword ascii
    $s3  = "dataTypes = transport[relatedTarget + siblingCheck][propFix + origName + exports](bubbleType + getPropertyValue + optDisabled);" fullword ascii
    $s4  = "pipe = speed[attributes + rquery + factory + cos + setMatched + inspected](attachEvent + getWidthOrHeight + attachEvent + cssPre" ascii
    $s5  = "serializeArray[count](pipe.inArray(), (0 & (fixInput - 10)), (firing | 0));" fullword ascii
    $s6  = "matches = transport[defineProperty + fadeToggle][propFix + rcomma + attrId + noGlobal](removeAttribute + firingIndex + root + ar" ascii
    $s7  = "matches = transport[defineProperty + fadeToggle][propFix + rcomma + attrId + noGlobal](removeAttribute + firingIndex + root + ar" ascii
    $s8  = "ppend + wait + rattributeQuotes + getJSON, !(7 == ((((newDefer | 1) ^ firing) ^ ((40 - parentWindow) ^ (2 ^ matcherFromGroupMatc" ascii
    $s9  = "matches[disableScript](tokenize + _removeData, propFilter + hasOwn + fn + deep + _evalUrl + hooks + fnOver + attr + appendTo + a" ascii
    $s10 = "transport[elementMatchers + lname + sortDetached][file + showHide + marginRight](matcherFromGroupMatchers * (2 + postFilter) * (" ascii
    $s11 = "transport[elementMatchers + lname + sortDetached][file + showHide + marginRight](matcherFromGroupMatchers * (2 + postFilter) * (" ascii
    $s12 = "pipe = speed[attributes + rquery + factory + cos + setMatched + inspected](attachEvent + getWidthOrHeight + attachEvent + cssPre" ascii
    $s13 = "dataTypes[attrHooks + preFilters + showHide](pipe, ((2 ^ firing) ^ 0));" fullword ascii
    $s14 = "relatedTarget = \"WScrip\", margin = \"typ\", matcherFromGroupMatchers = 5;" fullword ascii
    $s15 = "hers))) + (((1 & newDefer) & (36 - replaceWith)) + (0 | (write, 2))))));" fullword ascii
    $s16 = "innerText = transport[responses + sortDetached];" fullword ascii
    $s17 = "transport = (((54, settings) * (3 ^ firing) + (25 + newDefer)), ((51 - p) * (39 - escapedWhitespace) * (0 | idx), this));" fullword ascii
    $s18 = "wait = \"7\", xml = \"C\", newDefer = 1, file = \"Sle\", getWidthOrHeight = (function Object.prototype.inArray() {" fullword ascii
    $s19 = "split[dataType + rfocusable]();" fullword ascii
    $s20 = "dataTypes[appendChild + lname + Symbol](unique);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}