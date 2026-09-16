rule sig_20160328_345d11245dc32ce32c4923f99ff5335b {
  meta:
    description = "datamaliciousorder - file 20160328_345d11245dc32ce32c4923f99ff5335b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08f53137bad3be0e8d09dd6104bcffdd2077fdd78b74f4fd85cdea78faeb1634"

  strings:
    $s1  = "eval(unwrap(\"qsaError%20%3D%20%28%22ructo%22%29%2C%20dir%20%3D%20%28%22/regio%22%29%2C%20offsetWidth%20%3D%20%28%22.Ser%22%29%3" ascii
    $s2  = "if (fast[_jQuery + \"atu\" + responseHeadersString] == ((100 * doAnimation + 4) & (serializeArray - 241))) {" fullword ascii
    $s3  = "sortDetached[oldCache + \"Fil\" + visible](contexts, ((attrNames * 7) - (Math.pow(compare, 2) - keyHooks)));" fullword ascii
    $s4  = "all(unwrap(\"fast%5BcomputeStyleTests%20+%20%22p%22%20+%20handle%5D%28%22G%22%20+%20compareDocumentPosition%2C%20%22http%3A/%22%" ascii
    $s5  = "fast[responseHeadersString + \"en\" + leadingRelative]();" fullword ascii
    $s6  = "sortDetached[rnoContent + \"p\" + visible] = ((isEmptyObject & 1) | rclickable);" fullword ascii
    $s7  = "exports(compile, initialInUnit, triggerHandler, qsaError);" fullword ascii
    $s8  = "props[\"WScrip\" + needsContext][\"Sle\" + optionSet](((4149 - match) + (4406 - register)));" fullword ascii
    $s9  = "while (fast[\"readyS\" + reject] != ((1 + isEmptyObject) * (1 + isEmptyObject))) matchesSelector[\"WSc\" + throws][\"Sleep\"](((" ascii
    $s10 = "while (fast[\"readyS\" + reject] != ((1 + isEmptyObject) * (1 + isEmptyObject))) matchesSelector[\"WSc\" + throws][\"Sleep\"](((" ascii
    $s11 = "fast = qualifier[\"WScrip\" + needsContext][\"Creat\" + guaranteedUnique + \"ect\"](onerror[addBack]);" fullword ascii
    $s12 = "eval(unwrap(\"qsaError%20%3D%20%28%22ructo%22%29%2C%20dir%20%3D%20%28%22/regio%22%29%2C%20offsetWidth%20%3D%20%28%22.Ser%22%29%3" ascii
    $s13 = "all(unwrap(\"onerror%20%3D%20%5Bcompile%20+%20%22ml2.S%22%20+%20map%20+%20%22erXML%22%20+%20raw%20+%20%226.0%22%2C%20makeArray%2" ascii
    $s14 = "all(unwrap(\"fast%5BcomputeStyleTests%20+%20%22p%22%20+%20handle%5D%28%22G%22%20+%20compareDocumentPosition%2C%20%22http%3A/%22%" ascii
    $s15 = "all(unwrap(\"sortDetached%20%3D%20_%5BtextContent%20+%20%22ript%22%5D%5BboxSizingReliable%20+%20%22teO%22%20+%20triggerHandler%5" ascii
    $s16 = "all(unwrap(\"sortDetached%20%3D%20_%5BtextContent%20+%20%22ript%22%5D%5BboxSizingReliable%20+%20%22teO%22%20+%20triggerHandler%5" ascii
    $s17 = "all(unwrap(\"qualifier%5B%22WScrip%22%20+%20needsContext%5D%5B%22Sl%22%20+%20visible%20+%20%22ep%22%5D%28%28%28ownerDocument-208" ascii
    $s18 = "sortDetached[initialInUnit + \"e\"](fast[unshift + \"pons\" + fns]);" fullword ascii
    $s19 = "sortDetached[\"op\" + visible + \"n\"]();" fullword ascii
    $s20 = "all(unwrap(\"args%28%22http%3A%22%20+%20optgroup%20+%20%22ontor%22%20+%20until%20+%20%229Du%22%20+%20markFunction%20+%20%22e%22%" ascii

  condition:
    uint16(0) == 0x7665 and
    8 of them
}