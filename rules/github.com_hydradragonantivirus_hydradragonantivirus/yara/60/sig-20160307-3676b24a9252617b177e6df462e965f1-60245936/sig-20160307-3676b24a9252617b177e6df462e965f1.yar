rule sig_20160307_3676b24a9252617b177e6df462e965f1 {
  meta:
    description = "datamaliciousorder - file 20160307_3676b24a9252617b177e6df462e965f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51c73aa7555b669a11577ff5ad157ba60fc2002dd0e685d64e029e21b34b723b"

  strings:
    $x1  = "setOffset[delegateTarget](rinputs, implicitRelative + firing + hasClass + matcher + scripts + rdashAlpha + status + rjsonp + has" ascii
    $s2  = "hasContent[fadeToggle](toggle.opener(), ((converters & 1) * (optionSet & 1)), ((ajaxTransport * 2 + elementMatcher) - (0 | start" ascii
    $s3  = " ^ 47)), ((base | 0) * (Math.pow(len, 2) - mimeType) + (1 | optionSet)))) - (Math.pow((((41 | contentDocument) - (122 - option))" ascii
    $s4  = "setOffset[delegateTarget](rinputs, implicitRelative + firing + hasClass + matcher + scripts + rdashAlpha + status + rjsonp + has" ascii
    $s5  = "stopPropagation = _data[pointerleave + parents][sibling + addToPrefiltersOrTransports + param + firing](special + rbracket + mer" ascii
    $s6  = "_data[pointerleave + parents][last + getter](((progressContexts | 11144) & (removeEventListener | 4826)));" fullword ascii
    $s7  = "| 144), (Math.pow(wrapInner, 2) - propFix), 160))) / ((((lastModified, 0) | (boolHook, 12)) * ((Math.pow(check, 2) - innerHTML) " ascii
    $s8  = "_data = (11 * base * (3 + optionSet) * (1 ^ check), (((Math.pow(274, base) - 74756) / (check * 6 + base)), this));" fullword ascii
    $s9  = "ties * 19 + attrs) / (Math.pow(27, base) - 701)))))));" fullword ascii
    $s10 = "fix + content);" fullword ascii
    $s11 = "rfocusMorph = tweener[old + merge + reliableMarginLeft + index + newUnmatched + firing](defaultPrevented + stop + getPropertyVal" ascii
    $s12 = "toggle = rfocusMorph[getAttribute + set + add + booleans + Data + isArrayLike + getAll](argument + disable + obj) + preventDefau" ascii
    $s13 = "rfocusMorph = tweener[old + merge + reliableMarginLeft + index + newUnmatched + firing](defaultPrevented + stop + getPropertyVal" ascii
    $s14 = "toggle = rfocusMorph[getAttribute + set + add + booleans + Data + isArrayLike + getAll](argument + disable + obj) + preventDefau" ascii
    $s15 = "setOffset = _data[defaultPrevented + defer][body + parseJSON + reliableMarginLeft + rhtml](optDisabled + parsed + condense + pre" ascii
    $s16 = "stopPropagation[prototype + getById](setOffset[stopOnFalse + source + getText + emptyStyle]);" fullword ascii
    $s17 = ") | (converters + -1))) - ((globalEventContext, 153, Expr) ^ (3853 + resolve))) ^ (((3 * base + 2) | (converters * 0)) | ((open " ascii
    $s18 = "| (4 & innerHTML))), ((144 | base * 2 * check * 2) - ((ofType | 56) & (nodeType + 15))), (((css / 26) ^ (win - 1351)) / ((proper" ascii
    $s19 = " + rnoInnerhtml + swap, !(((((7 & isXML) ^ (2 | ofType)) * ((69, dataFilter, 14) + (attrNames - 6)) / (((optionSet | 1) | (isXML" ascii
    $s20 = "mentElement + 1079) / (els * 3 + elementMatcher))))) == (((Math.pow(((84 + innerHTML) & (52 * base + 7)), ((leadingRelative / 47" ascii

  condition:
    uint16(0) == 0x7277 and
    1 of ($x*) and 4 of them
}