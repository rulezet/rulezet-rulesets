rule _20160310_2d733d339fd8078e4b40901dcfc2db51_20160310_4b4c3e94f87c_600 {
  meta:
    description = "datamaliciousorder - from files 20160310_2d733d339fd8078e4b40901dcfc2db51.js, 20160310_4b4c3e94f87cb08b27eaef92ca228114.js, 20160310_72e22cf4c55cdf86f4b1ef3de738b97f.js, 20160310_8383811f7d944126519a1218f0d8aca1.js, 20160310_96ec9dce6930b62c90a5fddd7d811d46.js, 20160310_c56d7acf23cc837d7ab1cfe2828f1fb2.js, 20160310_cc46cbfe5bbb971bd4a8e47290003690.js, 20160310_edeaf4d708eb442190e74d7bdea01e6b.js, 20160310_f20a91927a3058764a1424495b785066.js, 20160310_f29ea237de53fa80efd971a12bb71657.js, 20160310_f2d87fa10bbac872258af76234f39ee0.js, 20160310_f7ca5d4771ef33679d17d1387b961960.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dedcbfa986abc2447cd7e78d66dee3eb51e8ef44a7a4fbaa01981b2314f655aa"
    hash2       = "e8f48ba61c77304d9a50eead2ff93b5379148e49e25242b3b65bb80d32c8d0e4"
    hash3       = "bcdbaa6341550f297fa6cb910a07539277eb1e1816fee5b8d5d6cc3f9b05a560"
    hash4       = "72bdb974f201a5b0be2bc0c1784ccf64e77346d8113c8fd30ea33e4e98781dc7"
    hash5       = "fe7dbe05f4af8ee4c4ca407e343261b295843f77f316df8e79bf31d5c4ccaa3e"
    hash6       = "aeab81403966b90dae58526712d4d2ba18a10374c604857cc3ce5a013f29c4d6"
    hash7       = "28c82a080ece4a206452d20798e21ed463fef1c968e4bb498dd1705cc4a50ffc"
    hash8       = "b9751970be6096714db23ff244908c9dcac71fd7992297db12feb74d4a67672f"
    hash9       = "8c258300301b1b3dedd4219f00fad2c98f984b6221a3a33998c22333c5c0cd81"
    hash10      = "c3f1552f71e284872bb2d9591090d0cc2f56bdf50ae64db45e1d7d72a4849618"
    hash11      = "d77c1e552801b09e4a44828938df0394b33000438d899249d5ae446dcb8cb264"
    hash12      = "85a2b2938c24fb44afc9a6cc52ebfdc5eda9c05e08dcd640e149b048189a06ff"

  strings:
    $s1  = "        //if ( (support.qsa = rnative.test( document.querySelectorAll )) ) {    Build QSA regex    Regex strategy adopted from D" ascii
    $s2  = "xplicitly     setting a boolean content attribute,     since its presence should be enough     http:bugs.jquery.com/ticket/12359" ascii
    $s3  = "        //Support: IE8, Opera 11-12.16     Nothing should be selected when empty strings follow ^= or $= or *=     The test attr" ascii
    $s4  = "    //}    Webkit/Opera - :checked should return selected option elements     http:www.w3.org/TR/2011/REC-css3-selectors-2011092" ascii
    $s5  = "    //}    Webkit/Opera - :checked should return selected option elements     http:www.w3.org/TR/2011/REC-css3-selectors-2011092" ascii
    $s6  = "ibute must be unknown in Opera but \\\"safe\\\" for WinRT     http:msdn.microsoft.com/en-us/library/ie/hh465388.aspx#attribute_s" ascii
    $s7  = "    //}    Support: Safari 8+, iOS 8+     https:bugs.webkit.org/show_bug.cgi?id=136851     In-page `selector#id sibing-combinato" ascii
    $s8  = "    //}    Support: Safari 8+, iOS 8+     https:bugs.webkit.org/show_bug.cgi?id=136851     In-page `selector#id sibing-combinato" ascii
    $s9  = "        //qSa(:focus) reports false when true (Chrome 21)   We allow this because of a bug in IE8/9 that throws an error   whene" ascii
    $s10 = "        //matchesSelector(:active) reports false when true (IE9/Opera 11.5)  rbuggyMatches = [];" fullword ascii
    $s11 = "//function( tag, context ) {    var elem,     tmp = [],     i = 0,      By happy coincidence, a (broken) gEBTN appears on Docume" ascii
    $s12 = "        //Support: IE8, Opera 11-12.16     Nothing should be selected when empty strings follow ^= or $= or *=     The test attr" ascii
    $s13 = "    //}    Support: Chrome<29, Android<4.4, Safari<7.0+, iOS<7.0+, PhantomJS<1.9.8+    if ( !div.querySelectorAll( \\\"[id~=\\\"" ascii
    $s14 = "        //}    Support: IE8     Boolean attributes and \\\"value\\\" are not treated correctly    if ( !div.querySelectorAll(" ascii
    $s15 = "    //}    Support: Chrome<29, Android<4.4, Safari<7.0+, iOS<7.0+, PhantomJS<1.9.8+    if ( !div.querySelectorAll( \\\"[id~=\\\"" ascii
    $s16 = "//Class  Expr.find[\\\"CLASS\\\"] = support.getElementsByClassName && function( className, context ) {   if ( typeof context.get" ascii
    $s17 = "//Class  Expr.find[\\\"CLASS\\\"] = support.getElementsByClassName && function( className, context ) {   if ( typeof context.get" ascii
    $s18 = "r selector` fails    if ( !div.querySelectorAll( \\\"a#\\\" + expando + \\\"+*\\\" ).length ) {     rbuggyQSA.push(\\\".#.+[+~]" ascii
    $s19 = "        //if ( (support.qsa = rnative.test( document.querySelectorAll )) ) {    Build QSA regex    Regex strategy adopted from D" ascii
    $s20 = "ver `document.activeElement` is accessed on an iframe   So, we allow :focus to pass through QSA all the time to avoid the IE err" ascii

  condition:
    (uint16(0) == 0x2f2f and (8 of them)
    ) or (all of them)
}