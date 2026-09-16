rule sig_20160401_5cb91539fe7108eb15931a979136f667 {
  meta:
    description = "datamaliciousorder - file 20160401_5cb91539fe7108eb15931a979136f667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e35d9351e84ceffad457fe4abe3b6cf3eefcb03646eb443c902f70e93b4fb36"

  strings:
    $s1  = "CDDSSFF = String[(\"mistletoe\",\"induction\",\"revenge\",\"f\")+(\"hankering\",\"trout\",\"diablo\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s2  = "lqMyPmmkl = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s3  = "lqMyPmmkl = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s4  = "EiztRz = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "    symbol.evaluation = symbol.downloading[(\"c\"+\"hD\"+\"rA\"+(\"quadrant\",\"doctors\",\"wayne\",\"t\")).replace(\"D\", CDDSS" ascii
    $s6  = "if (typeof(subsequently)===(\"electoral\",\"loose\",\"circlet\",\"u\")+\"ndef\"+\"in\"+\"ed\") subsequently = 0;" fullword ascii
    $s7  = "var DefUdd = skate + 5;" fullword ascii
    $s8  = "TDnPrvLIhw = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( dat" ascii
    $s9  = "ory\",\"parsonage\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "CDDSSFF = String[(\"mistletoe\",\"induction\",\"revenge\",\"f\")+(\"hankering\",\"trout\",\"diablo\",\"ro\")+\"mC\"+\"ha\"+\"rC" ascii
    $s11 = "        var redhead = BSfuntnX + \"/\" + flower + TlzTBsJl.shift();" fullword ascii
    $s12 = " !id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s13 = "ThIfKpQloy = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s14 = "Array.prototype.labels = function(){" fullword ascii
    $s15 = "   DMItuftevKo = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( " ascii
    $s16 = "        Dmvwqri = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s18 = "        WiOKNEX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii
    $s19 = "        downloading: this" fullword ascii
    $s20 = "        WiOKNEX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpty" ascii

  condition:
    uint16(0) == 0x716c and
    8 of them
}