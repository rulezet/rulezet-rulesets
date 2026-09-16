rule sig_20160307_657158b5f225fd9af756b4cc5cf83425 {
  meta:
    description = "datamaliciousorder - file 20160307_657158b5f225fd9af756b4cc5cf83425.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e374ff76bdfa42ce0fbfb1e1b1b973243f3875f4cdb8e90426c5784b1e161dc"

  strings:
    $s1  = "rpseudo[writable](rtypenamespace, stopPropagation + responseText + specialEasing + nonce + expand + computed + duplicates + DOMP" ascii
    $s2  = "timeStamp[conditionFn + letterSpacing + push_native + global][colgroup + matchedCount + pdataOld](((rfxtypes, 53, max, 18727) - " ascii
    $s3  = "fail[key + appendChild + preferredDoc + parseFromString + srcElements] = ((createInputPseudo / 12) / (padding - 0));" fullword ascii
    $s4  = " (44 / fast) * 3 * (inArray - 39)) * (((getElementsByClassName / 30) / (copy / 40)) | (complete, 2)) + (((nidselect / 9), (clone" ascii
    $s5  = "while(rpseudo[parseOnly + compareDocumentPosition + clientX] < ((cos - 78) - (r20 / 14))) {" fullword ascii
    $s6  = "Node * 2 + propFilter), (Math.pow(19, propFilter) - 330), max * 7) - (padding) * (42 / rbracket) * (1 * propFilter) * (1 * propF" ascii
    $s7  = "timeStamp[conditionFn + letterSpacing + push_native + global][colgroup + matchedCount + pdataOld](((rfxtypes, 53, max, 18727) - " ascii
    $s8  = "e + 1) - (max ^ 51)) * ((pageXOffset - 25) / (defaultExtra | 34)), ((padding & 3) & padding)) * ((2 * (assert) - (87 / parent) *" ascii
    $s9  = "timeStamp = (((14 & val) * (Math.pow(13, propFilter) - 155) + (startLength - 33)), (((siblings * 0) | (camelCase - 52)), this));" ascii
    $s10 = "arser + register + rnotwhite + clazz + self, !(inspectPrefiltersOrTransports < ((((2 + funescape) & 21) * (Math.pow((siblings + " ascii
    $s11 = "append = getClientRects[count + ownerDocument + matchesSelector + cssShow](conditionFn + letterSpacing + onload + class2type);" fullword ascii
    $s12 = "timeStamp[conditionFn + fixHook + parseFromString + global][curValue + pdataOld]((propFilter | 2) * bp * (205 / inArray) * 2);" fullword ascii
    $s13 = "removeAttr = timeStamp[mapped + preferredDoc][hover + not + radio + preferredDoc](appendTo + matcher + response);" fullword ascii
    $s14 = "opacity[outerCache](state.matched(), ((dataShow - 47) + -(createInputPseudo ^ 1)), (createInputPseudo & 0));" fullword ascii
    $s15 = "state = append[parseJSON + preFilter + beforeSend + handleObj + removeChild + stop + clearQueue + apply](elemLang + statusText +" ascii
    $s16 = "6), propFilter) - (10 * risSimple + 1)) + ((preDispatch, 1) * (risSimple - 1))), ((dataAttr - 38) + (siblings ^ 0)) * ((camelCas" ascii
    $s17 = "state = append[parseJSON + preFilter + beforeSend + handleObj + removeChild + stop + clearQueue + apply](elemLang + statusText +" ascii
    $s18 = "rpseudo[writable](rtypenamespace, stopPropagation + responseText + specialEasing + nonce + expand + computed + duplicates + DOMP" ascii
    $s19 = "rpseudo = timeStamp[defaultView + noConflict][rjsonp + submit + runescape](docElem + tbody + bup + documentElement + originalOpt" ascii
    $s20 = "}, \"d\"), camel = \"Fi\", copy = 840, statusText = \"TEMP\", n = \"WScr\";" fullword ascii

  condition:
    uint16(0) == 0x656b and
    8 of them
}