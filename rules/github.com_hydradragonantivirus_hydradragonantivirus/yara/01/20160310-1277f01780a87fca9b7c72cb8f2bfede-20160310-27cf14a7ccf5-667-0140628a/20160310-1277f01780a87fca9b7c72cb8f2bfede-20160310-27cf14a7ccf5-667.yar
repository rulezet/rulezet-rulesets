rule _20160310_1277f01780a87fca9b7c72cb8f2bfede_20160310_27cf14a7ccf5_667 {
  meta:
    description = "datamaliciousorder - from files 20160310_1277f01780a87fca9b7c72cb8f2bfede.js, 20160310_27cf14a7ccf57b6f06aa87360cf3a8c1.js, 20160310_2b8e0a501c3337d8db857e1f8f003ae4.js, 20160310_3aa4665868f5269ff944197e6d00cb0c.js, 20160310_3b19a76544e2d79097592e4561a2a716.js, 20160310_44726f02d0835265533414a9683e357b.js, 20160310_5315a04c64d19cea8f9021d328750da2.js, 20160310_7b03bb802cf1a43248688b7914e9306a.js, 20160310_a09feedd928be0f173d4c3af09dafec8.js, 20160310_bd15baf8763fc7528ea38521903790f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f9a0656f0a9569b9502293b724784f1d4e8caf607d0b19045cfd06bdae15d86"
    hash2       = "ab4a0646209a6cc9e9f73c12bb5ead8c605579e0c57f4ea4052d37e8ba11c37e"
    hash3       = "117a5fa4e6059b0f4f608682ba2048b4e3dcef1e9b496e1671da27450a539fa2"
    hash4       = "19f37008fddee4a295fdf5e9254c051666707f2804dbb8d3462fd1e60c219da7"
    hash5       = "5c74b2384ad4526319ab65068e555c1ff1728606ca989c0e260c5dd070980e50"
    hash6       = "d6849d75baf1c73cfe5168f8e1d7430eee612952aa1aeef548721000dbd16491"
    hash7       = "eff130fb031fe4aff70b890776ce22806d2d7a9ab68e72edcb380d65675ef1be"
    hash8       = "89d3976a320eea7e2de59d3cfd9e5d3b444244dc6de3b57665f0ef01e82e82d5"
    hash9       = "e21ad3856a1465c60db741484ceac9431bdcf8f411fae377b5583c56b2478149"
    hash10      = "b77c02a875b63bcbbdd41ef86965d27a0b27e09d30935bd46e4ae4be27c8af62"

  strings:
    $s1  = "        //}   Sort on method existence if only one input has compareDocumentPosition   var compare = !a.compareDocumentPosition " ascii
    $s2  = "//}    Opera 10-11 does not throw on post-comma invalid pseudos    div.querySelectorAll(\\\"*,:x\\\");    rbuggyQSA.push(\\\",.*" ascii
    $s3  = "    //   Disconnected nodes   if ( compare & 1 ||    (!support.sortDetached && b.compareDocumentPosition( a ) === compare) ) {" fullword ascii
    $s4  = "//}    Opera 10-11 does not throw on post-comma invalid pseudos    div.querySelectorAll(\\\"*,:x\\\");    rbuggyQSA.push(\\\",.*" ascii
    $s5  = "- !b.compareDocumentPosition;   if ( compare ) {    return compare;   " fullword ascii
    $s6  = "        //Element contains another   Purposefully self-exclusive   As in, an element does not contain itself  contains = hasComp" ascii
    $s7  = "      a.compareDocumentPosition && a.compareDocumentPosition( bup ) & 16    ));   } :   function( a, b ) {    if ( b ) {     whi" ascii
    $s8  = "//}    Maintain original order    return sortInput ?     ( indexOf( sortInput, a ) - indexOf( sortInput, b ) ) :     0;   " fullword ascii
    $s9  = "rredDoc && contains(preferredDoc, a) ) {     return -1;    }    if ( b === document || b.ownerDocument === preferredDoc && conta" ascii
    $s10 = "        //}   Sort on method existence if only one input has compareDocumentPosition   var compare = !a.compareDocumentPosition " ascii
    $s11 = "    //    Choose the first element that is related to our preferred document    if ( a === document || a.ownerDocument === prefe" ascii
    $s12 = "//This should fail with an exception     Gecko does not error, returns false instead    matches.call( div, \\\"[s!=\\\"\\\"]:x" ascii
    $s13 = "//This should fail with an exception     Gecko does not error, returns false instead    matches.call( div, \\\"[s!=\\\"\\\"]:x" ascii
    $s14 = "        //Element contains another   Purposefully self-exclusive   As in, an element does not contain itself  contains = hasComp" ascii
    $s15 = "//assert(function( div ) {     Check to see if it\\\"s possible to do matchesSelector     on a disconnected node (IE 9)    suppo" ascii
    $s16 = "= b && b.parentNode;    return a === bup || !!( bup && bup.nodeType === 1 && (     adown.contains ?      adown.contains( bup ) :" ascii
    $s17 = "    //}   Calculate position if both inputs belong to the same document   compare = ( a.ownerDocument || a ) === ( b.ownerDocume" ascii
    $s18 = "        //Document order sorting  sortOrder = hasCompare ?  function( a, b ) {" fullword ascii

  condition:
    (uint16(0) == 0x2f2f and (8 of them)
    ) or (all of them)
}