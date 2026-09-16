rule _20160314_7368361105ab30664fc9ad8c022a1e51_20160314_fe02f096910b_4091 {
  meta:
    description = "datamaliciousorder - from files 20160314_7368361105ab30664fc9ad8c022a1e51.js, 20160314_fe02f096910be10637f8ad163800ae2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49e3b77c38abe48c85df71fc010701b0e8d75da8bc552194f6314ccf4340981e"
    hash2       = "42d708a17f38ff07cb67049ad163bf9e87e28e7b76d80264461f4a50a3b35b4c"

  strings:
    $s1 = " elem.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = " Do not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11 )" ascii
    $s3 = "xtContent === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstChil" ascii
    $s4 = " {    Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem.te" ascii
    $s5 = "lem; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   return" ascii

  condition:
    ((uint16(0) == 0x436b or uint16(0) == 0x434b) and (all of them)
    ) or (all of them)
}