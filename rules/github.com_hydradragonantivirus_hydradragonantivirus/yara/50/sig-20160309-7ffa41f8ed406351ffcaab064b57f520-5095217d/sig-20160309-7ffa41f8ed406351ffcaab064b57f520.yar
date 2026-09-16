rule sig_20160309_7ffa41f8ed406351ffcaab064b57f520 {
  meta:
    description = "datamaliciousorder - file 20160309_7ffa41f8ed406351ffcaab064b57f520.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03b5216ad41573480fb8e7f1cb19a07ad41b8cc2c16b0044b23884a527cfc255"

  strings:
    $s1  = "implicitRelative[each + mouseleave](ajaxTransport, camelKey + duplicates + callbackExpect + accepts + prevObject + tweeners + pa" ascii
    $s2  = "context, (254 & ontype), (4 | context))) + (((28 - check) * (15 * context + 6) + (delegateCount | 1)), ((Math.pow(scriptCharset," ascii
    $s3  = "(Math.pow(check, 2) - reliableMarginLeftVal) & (63 & elemdisplay)) & ((0 | disableScript) * (Math.pow(9, context) - 66) + (deleg" ascii
    $s4  = "ateCount | 1))) - ((context * 17 - (disableScript + 7)) ^ (Math.pow((cssExpand - 50), (defaultPrefilter - 4)) - (preDispatch | 1" ascii
    $s5  = "markFunction[ready + matchAnyContext + createButtonPseudo] = (content + -1);" fullword ascii
    $s6  = " 2) - matchedCount) | (336 / global)), ((56 * context + 15) & (valueIsBorderBox - 106)), ((content * 1) & (content * 1)))) * (((" ascii
    $s7  = "nodeName[removeAttribute](map.anim(), ((1 * delegateCount) & (1 ^ delegateCount)), ((1100 / setOffset) - (Math.pow(41, context) " ascii
    $s8  = "nodeName[removeAttribute](map.anim(), ((1 * delegateCount) & (1 ^ delegateCount)), ((1100 / setOffset) - (Math.pow(41, context) " ascii
    $s9  = "oldfire = dispatch[matcher + optDisabled + compiled + selected + tbody](onload + funescape + getWidthOrHeight + selection + coun" ascii
    $s10 = "oldfire = dispatch[matcher + optDisabled + compiled + selected + tbody](onload + funescape + getWidthOrHeight + selection + coun" ascii
    $s11 = "style[domManip + setFilters] = (1 * (n - 4));" fullword ascii
    $s12 = "ready = \"p\", tweeners = \"om/sys\", postFinder = \"ADOD\";" fullword ascii
    $s13 = "map = oldfire[iNoClone + Data + currentTime + mouseleave + args + guid](pdataOld + evt + matchContext) + radioValue + rrun + oMa" ascii
    $s14 = "map = oldfire[iNoClone + Data + currentTime + mouseleave + args + guid](pdataOld + evt + matchContext) + radioValue + rrun + oMa" ascii
    $s15 = "content = 1;" fullword ascii
    $s16 = "dataAndEvents[camelCase + cos + isXMLDoc + specialEasing](map, ((content * 2) & (context | 0)));" fullword ascii
    $s17 = "dataAndEvents = escaped[prepend + setRequestHeader + tbody][uniqueID + swing + preFilter](postFinder + fnOut + globalEventContex" ascii
    $s18 = "dataAndEvents = escaped[prepend + setRequestHeader + tbody][uniqueID + swing + preFilter](postFinder + fnOut + globalEventContex" ascii
    $s19 = "dataAndEvents[sel + push](slideToggle);" fullword ascii
    $s20 = "implicitRelative[pixelMarginRight + notify]();" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}