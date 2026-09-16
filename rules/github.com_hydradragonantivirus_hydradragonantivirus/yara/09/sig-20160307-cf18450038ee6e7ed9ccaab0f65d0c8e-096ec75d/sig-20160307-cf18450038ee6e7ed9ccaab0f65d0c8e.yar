rule sig_20160307_cf18450038ee6e7ed9ccaab0f65d0c8e {
  meta:
    description = "datamaliciousorder - file 20160307_cf18450038ee6e7ed9ccaab0f65d0c8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb6a4efc941d9e0ec220a277a0155994b2cf1c0ab698c5f4c53bcbb49c7f40c7"

  strings:
    $s1  = ") + (Math.pow((letterSpacing, 61, parseJSON, 15), (preDispatch, 158, status, 2)) - (udataCur, 210, overwritten, 205))), (((token" ascii
    $s2  = "t, 229), (focusin + 1))) ^ (((ridentifier | 0) * (err | 1) + (disabled ^ 1)) - ((focusin * 15) + (keepData - 34)))))));" fullword ascii
    $s3  = " !(3 < (((((disabled ^ 17) * (focusin * 2) + (ridentifier ^ 14)) * (Math.pow((focusin * 3), (callbackName - 26)) - (dequeue + 3)" ascii
    $s4  = "augmentWidthOrHeight[remaining + createElement](fns, test + isHidden + preexisting + overflowX + div1 + activeElement + wrapAll," ascii
    $s5  = "defineProperty = initialInUnit[nid + forward];" fullword ascii
    $s6  = "valueParts, 53, keepData, 44)) ^ ((rmouseEvent - 304) / (disabled | 28)))) - ((((disabled ^ 0) & (focusin & 1)) ^ ((originalEven" ascii
    $s7  = "augmentWidthOrHeight = initialInUnit[setDocument + mouseenter + eq][pdataCur + opener + method + rxhtmlTag](addEventListener + p" ascii
    $s8  = "cleanData = timer[finish + matchers + tag + speed + isBorderBox + hasCompare + compiled](setTimeout + step) + complete + contain" ascii
    $s9  = "cleanData = timer[finish + matchers + tag + speed + isBorderBox + hasCompare + compiled](setTimeout + step) + complete + contain" ascii
    $s10 = "while (augmentWidthOrHeight[wrapMap + e + trigger + indirect + completeDeferred + tfoot] < ((focusin * 4) / (focusin))) {" fullword ascii
    $s11 = "initialInUnit = (((132 | i) ^ (38 * genFx + 12)), (((Math.pow(returnValue, 2) - callbackName) | (2 ^ err)), this));" fullword ascii
    $s12 = "augmentWidthOrHeight = initialInUnit[setDocument + mouseenter + eq][pdataCur + opener + method + rxhtmlTag](addEventListener + p" ascii
    $s13 = "isBorderBox = \"ironm\", opener = \"eate\", ridentifier = 4, text = 40, addEventListener = \"MSX\", sortOrder = \"e\";" fullword ascii
    $s14 = "getById = initial;" fullword ascii
    $s15 = "forward = \"cript\";" fullword ascii
    $s16 = "rnamespace[getById](cleanData.matchesSelector(), (disabled | (0 ^ disabled)), (0 & (disabled | 1)));" fullword ascii
    $s17 = "augmentWidthOrHeight[indirect + setGlobalEval]();" fullword ascii
    $s18 = "click[cssHooks + replaceChild + querySelectorAll + sortOrder](cleanData, ((16 / done) * 2));" fullword ascii
    $s19 = "click[hooks + rmultiDash + tfoot](augmentWidthOrHeight[random + removeAttribute + inPage]);" fullword ascii
    $s20 = "height[swing + bup + map] = disabled;" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}