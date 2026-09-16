rule sig_20160309_9ab3a2c43cfe0556b7f52d4f5c59f952 {
  meta:
    description = "datamaliciousorder - file 20160309_9ab3a2c43cfe0556b7f52d4f5c59f952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f94746dac56a53a42c77bec580442624ba046c90cee2f728ce38448d582e50"

  strings:
    $s1  = "size = col[target + offsetWidth + stopOnFalse + parent + Data + contains + html + script](dirruns + ajaxPrefilter) + transport +" ascii
    $s2  = "size = col[target + offsetWidth + stopOnFalse + parent + Data + contains + html + script](dirruns + ajaxPrefilter) + transport +" ascii
    $s3  = "attrHandle[fontWeight](set + originAnchor + compare, urlAnchor + classes + letterSpacing + e + selection + originalProperties + " ascii
    $s4  = "var dirruns = \"%TEMP%\";" fullword ascii
    $s5  = "container + operator + unshift + async + defaultPrefilter + rfocusable + has + ontype, !(((((45 - collection) | (1 + _default)) " ascii
    $s6  = "prevAll = attrHandle[trim + postSelector + getComputedStyle + rtrim];" fullword ascii
    $s7  = "getter = \"ADO\", target = \"Exp\";" fullword ascii
    $s8  = "capName[reliableMarginLeft + unquoted + makeArray + escapedWhitespace](size, ((19 - rheader) + (0 | _default)));" fullword ascii
    $s9  = "col = finish[check + hide + slideToggle + innerHTML + parseXML](timers + parseOnly + host + marginDiv);" fullword ascii
    $s10 = "capName = keyCode[specified + tfoot][always + setter + factory](getter + diff + parseXML + list);" fullword ascii
    $s11 = "collection = 45, getComputedStyle = \"se\", reliableMarginLeft = \"sav\";" fullword ascii
    $s12 = " - (mouseenter, 172, soFar))))) > 10));" fullword ascii
    $s13 = "keyCode[specified + tfoot][split + click](((8712 | pixelPosition) ^ (74 + serialize)));" fullword ascii
    $s14 = "seed = \".scr\";" fullword ascii
    $s15 = "attrHandle = keyCode[pushStack + win][always + emptyStyle + offsetHeight + ct](rprotocol + val + width);" fullword ascii
    $s16 = "finish = keyCode[specified + tfoot];" fullword ascii
    $s17 = "e))) * ((504 / location) / 2 * addClass) * ((0 ^ fireGlobals) + 2) * (((when, 121) - (sortOrder | 4)) - ((_default ^ 6) ^ (compu" ascii
    $s18 = "leadingRelative = \"dd\", setter = \"teObj\", pixelPosition = 6147, unquoted = \"eToFi\", script = \"gs\", specified = \"WScri\"" ascii
    $s19 = "operator = \"thai.c\"," fullword ascii
    $s20 = "host = \".Sh\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}