rule sig_20160311_9d5af6835087f09049009d15780b5efd {
  meta:
    description = "datamaliciousorder - file 20160311_9d5af6835087f09049009d15780b5efd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62ae1cec18f01048add546555d174da0ae63e5e6009d5ec78e952fab4440ad0b"

  strings:
    $s1  = "parentWindow[\"op\".capName() + before](\"GE\" + structure, \"http:/\" + prev + \"umy_a\".capName() + delegateTarget + \".repu\"" ascii
    $s2  = "ath.pow(getElementsByTagName, (78, offsetParent, 208, attrId)) - (1536 | xhrFields)))) - ((97 + script), (112 - guid), (132 + sr" ascii
    $s3  = "writable = access[\"Cre\" + currentTarget + \"bje\".capName() + rootjQuery](\"WScri\" + firing + \"Shell\");" fullword ascii
    $s4  = " & 1) | (manipulationTarget * 2 + attrId)) * ((150, elementMatcher, 221, attrId) & 3)) | (((load + 0) * (returnFalse + 26)) | (M" ascii
    $s5  = "Handler + \"pl/08h\" + tbody, !((((parseJSON - 42) * (((ajax, 50, getElementsByTagName) + (24 - qualifier)) & ((38 + module) - (" ascii
    $s6  = "parentWindow[\"op\".capName() + before](\"GE\" + structure, \"http:/\" + prev + \"umy_a\".capName() + delegateTarget + \".repu\"" ascii
    $s7  = "rnoInnerhtml[\"Ru\".capName() + specified](getAttributeNode.capName(((3 * attrId) + (Math.pow(51, attrId) - 2518))), (position /" ascii
    $s8  = "rnoInnerhtml[\"Ru\".capName() + specified](getAttributeNode.capName(((3 * attrId) + (Math.pow(51, attrId) - 2518))), (position /" ascii
    $s9  = "fx[\"ty\" + childNodes] = ((Math.pow(155, attrId) - 23778), (load & 1));" fullword ascii
    $s10 = "getAttributeNode = writable[ct + \"Env\".capName() + disabled + \"nment\" + byElement + \"gs\"](oldCache + \"%/\".capName()) + s" ascii
    $s11 = "window[\"sav\" + tokenCache + \"le\".capName()](getAttributeNode, ((detach, 1) * (_data / 22)));" fullword ascii
    $s12 = " - Deferred)))) / (((23, load) & 1) * attrId) * (((5 * detach + 2) - (n - 23)) | ((curCSS | 34) / attrId * 7))) == (((((position" ascii
    $s13 = "c), (179, wrap, 98, attrId)) * (((598 / isBorderBox) - 2 * el) - (9 / el) * (46 - parseJSON)) * (((80 | origFn) / (1927 / linear" ascii
    $s14 = "67 - overflow)), ((26 / name) + -1));" fullword ascii
    $s15 = "function postSelector() {" fullword ascii
    $s16 = "getAttributeNode = writable[ct + \"Env\".capName() + disabled + \"nment\" + byElement + \"gs\"](oldCache + \"%/\".capName()) + s" ascii
    $s17 = "visibility[testContext + \"se\"]();" fullword ascii
    $s18 = " + \"iveE\" + isSuccess + \"nt\" + hidden + \"s\".capName() + th + \"r\";" fullword ascii
    $s19 = "access = factory[\"WScri\" + selectedIndex];" fullword ascii
    $s20 = "n = 62, includeWidth = 173, hidden = \".\", wrap = 172;" fullword ascii

  condition:
    uint16(0) == 0x7962 and
    8 of them
}