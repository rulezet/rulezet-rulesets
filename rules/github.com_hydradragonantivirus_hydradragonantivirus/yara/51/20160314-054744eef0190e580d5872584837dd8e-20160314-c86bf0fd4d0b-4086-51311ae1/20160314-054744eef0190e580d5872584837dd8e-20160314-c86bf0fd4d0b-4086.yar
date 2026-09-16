rule _20160314_054744eef0190e580d5872584837dd8e_20160314_c86bf0fd4d0b_4086 {
  meta:
    description = "datamaliciousorder - from files 20160314_054744eef0190e580d5872584837dd8e.js, 20160314_c86bf0fd4d0b1bcd7028d25cda3141fd.js, 20160314_cf5b1d499d3ebd4f00c10b1434a74ad3.js, 20160314_d3e82cc4651419f3f7e73e3711736afe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "538043d6a790bbc71896388acc352be371c00dbdaacea65913669c133ca042c2"
    hash2       = "3cf60e3b8df45c6076f1ed075c433b895e0c0a09b19bdf0ce7ff1a54d994968f"
    hash3       = "06aacd4740a4624bb284a5f0e222313a721314c4298439734baf8033029b4b6c"
    hash4       = "4733bf69b2c38e823e40ba7a1d5439fc259db7751d752b33f88c4db3f840065f"

  strings:
    $s1 = "rn elem.nodeValue;  }   Do not include comment or processing instruction nodes\";" fullword ascii
    $s2 = "   Do not traverse comment nodes    ret += getText( node );   }  } else if ( nodeType === 1 || nodeType === 9 || nodeType === 11" ascii
    $s3 = "textContent === \\\"string\\\" ) {    return elem.textContent;   } else {     Traverse its children    for ( elem = elem.firstCh" ascii
    $s4 = " ) {    Use textContent for elements    innerText usage removed for consistency of new lines (jQuery #11153)   if ( typeof elem." ascii
    $s5 = " elem; elem = elem.nextSibling ) {     ret += getText( elem );    }   }  } else if ( nodeType === 3 || nodeType === 4 ) {   retu" ascii

  condition:
    ((uint16(0) == 0x4a61 or uint16(0) == 0x6968 or uint16(0) == 0x7046 or uint16(0) == 0x6f65) and (all of them)
    ) or (all of them)
}