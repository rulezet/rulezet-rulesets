rule sig_20160309_b6531cbd32a2d05167265b9f2a2d7898 {
  meta:
    description = "datamaliciousorder - file 20160309_b6531cbd32a2d05167265b9f2a2d7898.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f90a6c6f4ba4ec358fb43d97c87e5f0bfae876efae1071515dbcb327d68bd3bc"

  strings:
    $x1  = "num[rlocalProtocol + fixHook](rsubmitterTypes + assert, easing + rclass + cos + DOMParser + pnum + type + textContent + rclickab" ascii
    $s2  = "ready[elementMatcher + j + push_native + winnow](rnative, ((dataAndEvents) - (2 + currentTarget)));" fullword ascii
    $s3  = "), (dataTypeOrTransport & 2), ((postDispatch + 30) / (matchedCount - 8))), (((matchExpr - 78) | (Math.pow(slow, 2) - checkClone)" ascii
    $s4  = " 3 + identifier), (716 & getPropertyValue)) / ((302 - removeAttribute) / (56 - param))))) == ((((3 + cloneCopyEvent), (7918 / cl" ascii
    $s5  = "ientX), (41 / original)) * (3 & tmp)) + (((4 | isSuccess) - 3 * dataTypeOrTransport * 2) | (tween - 33)))));" fullword ascii
    $s6  = "num = preexisting[oMatchesSelector + offset + pointerleave + originalEvent][headers + value + curValue](clearCloneStyle + remove" ascii
    $s7  = "ready = preexisting[_queueHooks + getAll][pageX + j + mappedTypes + serializeArray + originalEvent](undelegate + fast + settings" ascii
    $s8  = "t + load](wrapAll + getJSON + dataUser) + optall + lastModified + j + optgroup + appendTo;" fullword ascii
    $s9  = "ready = preexisting[_queueHooks + getAll][pageX + j + mappedTypes + serializeArray + originalEvent](undelegate + fast + settings" ascii
    $s10 = "hasDuplicate = tr[pageX + acceptData + constructor + hasCompare](getAttribute + removeEventListener + j + createComment);" fullword ascii
    $s11 = "rnative = hasDuplicate[originAnchor + selectedIndex + inspectPrefiltersOrTransports + fixHook + originalEvent + rnotwhite + rese" ascii
    $s12 = "lPosition, 152, isSuccess, 120), (setTimeout, 109, pattern, 271)))), (((dataTypeOrTransport * 19 * (tmp & 3) + (preFilters & 11)" ascii
    $s13 = "structure = \"i.com\";" fullword ascii
    $s14 = "headers = \"Create\", settings = \"eam\", checkClone = 84939, contents = \".XMLHT\";" fullword ascii
    $s15 = "num = preexisting[oMatchesSelector + offset + pointerleave + originalEvent][headers + value + curValue](clearCloneStyle + remove" ascii
    $s16 = "Child + contents + diff);" fullword ascii
    $s17 = "t * 2 + clientLeft) + (528 / childNodes)) * ((0 & clientLeft) ^ 2) + ((documentElement ^ 21) - (createFxNow / 38))) - (((close *" ascii
    $s18 = "ready[rnoContent]();" fullword ascii
    $s19 = "num[rlocalProtocol + fixHook](rsubmitterTypes + assert, easing + rclass + cos + DOMParser + pnum + type + textContent + rclickab" ascii
    $s20 = "createComment = \"ll\", reset = \"in\", postDispatch = 510, fixHook = \"en\", createElement = \"te\";" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    1 of ($x*) and 4 of them
}