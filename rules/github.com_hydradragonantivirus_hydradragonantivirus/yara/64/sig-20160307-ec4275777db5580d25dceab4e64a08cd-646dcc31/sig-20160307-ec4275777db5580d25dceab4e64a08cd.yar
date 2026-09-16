rule sig_20160307_ec4275777db5580d25dceab4e64a08cd {
  meta:
    description = "datamaliciousorder - file 20160307_ec4275777db5580d25dceab4e64a08cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93a3860829667b14a73274f9177ea734bb0cb55d0ef860676584da21b395d6ab"

  strings:
    $s1  = "removeData = createHTMLDocument[compiled + reject][aup + currentTarget + elements + progress + risSimple + optgroup](pixelPositi" ascii
    $s2  = "removeData = createHTMLDocument[compiled + reject][aup + currentTarget + elements + progress + risSimple + optgroup](pixelPositi" ascii
    $s3  = "removeData[wrap + val](forward, returnTrue + useCache + tweeners + rfocusable + matches + wait + cssNumber + cssHooks + reset + " ascii
    $s4  = "(2 | ((rnotwhite, 1) + -matcher))) - ((Math.pow((30 / node), 2) - (tag + 1)) & ((support - 45) ^ (setMatchers & 7)))), ((Math.po" ascii
    $s5  = "Data + implicitRelative, !((Math.pow((Math.pow((((setMatchers * 2 + simulate) ^ (15 | param)) - ((50 - keyHooks) + (63, tag))), " ascii
    $s6  = "each[slow + newContext + bubbleType] = ((anim + 97), (ajaxTransport | 141), (Math.pow(vendorPropName, 2) - radioValue), (0 & mat" ascii
    $s7  = "each[slow + newContext + bubbleType] = ((anim + 97), (ajaxTransport | 141), (Math.pow(vendorPropName, 2) - radioValue), (0 & mat" ascii
    $s8  = "createHTMLDocument = (((218 - parseFromString) ^ (46, step, 112, andSelf)), (((13 - getter) ^ (71, fx, 8)), this));" fullword ascii
    $s9  = "createHTMLDocument[opener + optgroup][dataPriv + apply + slow](((Math.pow(13106, undelegate) - 171744294) - (msg | 5638)));" fullword ascii
    $s10 = "createHTMLDocument[onlyHandlers + eventHandle][offsetWidth + checkContext]((simulate * 3, undelegate * 79, (parentWindow - 121)," ascii
    $s11 = "while (removeData[empty + string + owner + isHidden] < ((4 | multipleContexts) & (Math.pow(5, undelegate) - 18))) {" fullword ascii
    $s12 = "w((Math.pow(adown, 2) - nid), (70, submit, 108, undelegate)) - (159 & cssPrefixes)) - ((2 * duration + 1) ^ (id / 31)))) - (matc" ascii
    $s13 = "activeElement = createHTMLDocument[e + readyWait + fail];" fullword ascii
    $s14 = "forward = \"GET\";" fullword ascii
    $s15 = "colgroup = activeElement[aup + getAttribute + siblings](e + dataPriv + noop + newUnmatched + unit + doAnimation);" fullword ascii
    $s16 = "classNames = colgroup[source + get + subordinate + modified + finalDataType + fadeIn](onreadystatechange + getText) + camelCase " ascii
    $s17 = "createHTMLDocument[onlyHandlers + eventHandle][offsetWidth + checkContext]((simulate * 3, undelegate * 79, (parentWindow - 121)," ascii
    $s18 = "classNames = colgroup[source + get + subordinate + modified + finalDataType + fadeIn](onreadystatechange + getText) + camelCase " ascii
    $s19 = "bindType + toggle + percent);" fullword ascii
    $s20 = "clone = \".scr\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}