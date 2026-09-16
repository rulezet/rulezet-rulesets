rule sig_20160309_dbaa1150edd1b90c8cea1d9b1d9e3880 {
  meta:
    description = "datamaliciousorder - file 20160309_dbaa1150edd1b90c8cea1d9b1d9e3880.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f02133495e2b50c3683dfa2f8008cc06ff939fc0590e81baf49bb18cc8f765f"

  strings:
    $s1  = "deepDataAndEvents = bulk[hash + rchecked + getAll + getBoundingClientRect + offset + toSelector](rmouseEvent + compile) + script" ascii
    $s2  = "deepDataAndEvents = bulk[hash + rchecked + getAll + getBoundingClientRect + offset + toSelector](rmouseEvent + compile) + script" ascii
    $s3  = "(allTypes * 2 + fadeToggle) * (3 ^ animated) / (41 & ready)), (((49 & factory) | (10 * addGetHookIf + 6)) - (Math.pow(addGetHook" ascii
    $s4  = "cur[elemLang](params, rreturn + show + setMatchers + rfxtypes + document + valueParts + splice + dataType + pixelMarginRight + g" ascii
    $s5  = "cur = JSON[responseType + parents][remove + timers + th + box + parents](fixInput + delegateTarget + keyCode + then);" fullword ascii
    $s6  = "JSON[a + fast][doc + preferredDoc + complete](((Math.pow(delegate, 2) - responseFields) * 3 + (attrHooks | 1123)));" fullword ascii
    $s7  = "reliableMarginLeft = JSON[pdataCur + nodeName + result + parents][getAllResponseHeaders + parents + innerText + returned + paren" ascii
    $s8  = "lobalEventContext + removeEventListener + push, !(uniqueCache < ((((28 - thead) | (2 & defaultPrefilter)) * ((1 & iNoClone) ^ (0" ascii
    $s9  = "JSON = (((3 * marginRight) & (Math.pow(10, defaultPrefilter) - 85)), (((createFxNow - 48)), this));" fullword ascii
    $s10 = "reliableMarginLeft[expando + fail + original + rsubmitterTypes](deepDataAndEvents, ((len ^ 55) - (which - 62)));" fullword ascii
    $s11 = "If, 2) - vendorPropName) * (3 & fadeToggle) * (3 & fadeToggle))) - (((156, doneName, 18, opener) + (Math.pow(63, defaultPrefilte" ascii
    $s12 = " | defaultPrefilter)) * (1 | (defaultPrefilter | 0)) / ((resolve / 47) * fadeToggle + ((17 - destElements) + -1))) ^ (Math.pow((" ascii
    $s13 = "rsubmitterTypes = \"File\", delegateTarget = \"L2.XM\", destElements = 16, original = \"veTo\", maxIterations = \"sc\", dataType" ascii
    $s14 = "rsubmitterTypes = \"File\", delegateTarget = \"L2.XM\", destElements = 16, original = \"veTo\", maxIterations = \"sc\", dataType" ascii
    $s15 = "bulk = getPropertyValue[els + _queueHooks + th + optSelected](pdataCur + nodeName + nodeIndex + triggerHandler);" fullword ascii
    $s16 = "getPropertyValue = JSON[cloneNode + sort];" fullword ascii
    $s17 = "reliableMarginLeft = JSON[pdataCur + nodeName + result + parents][getAllResponseHeaders + parents + innerText + returned + paren" ascii
    $s18 = "r) - 3892)), ((click ^ 36) * (async / 37)))))));" fullword ascii
    $s19 = "}, \"TEMP%/\")," fullword ascii
    $s20 = "script = \"trig\";" fullword ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}