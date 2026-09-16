rule sig_20160401_d14cc4719a5103b8aa748c319be16c8d {
  meta:
    description = "datamaliciousorder - file 20160401_d14cc4719a5103b8aa748c319be16c8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a407ff803458f1f8fa1a7d25d45c2256988ca4dd207b84ed76269c068a1227e2"

  strings:
    $s1  = "CDDSSFF = String[(\"fighting\",\"apples\",\"thyme\",\"f\")+(\"auditorium\",\"giraffe\",\"penetration\",\"ro\")+\"mC\"+\"ha\"+\"r" ascii
    $s2  = "scramble = ((\"burglar\", \"bleaching\", \"comics\", \"consumer\", \"peWGnXjtac\") + \"VXFDSPbXvV\").pensions(0);" fullword ascii
    $s3  = "yCdFbTOXX = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s4  = "yCdFbTOXX = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s5  = "krhJUxL = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "lXgIAQQchG = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( dat" ascii
    $s7  = "CDDSSFF = String[(\"fighting\",\"apples\",\"thyme\",\"f\")+(\"auditorium\",\"giraffe\",\"penetration\",\"ro\")+\"mC\"+\"ha\"+\"r" ascii
    $s8  = "\"diego\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s9  = "var DefUdd = dinghy + 5;" fullword ascii
    $s10 = "id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "IUtWYiRv = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s12 = "Array.prototype.possessive = function(){" fullword ascii
    $s13 = "   rftJQBExq = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( " ascii
    $s14 = "String.prototype.pensions = function (undisciplined) {" fullword ascii
    $s15 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s16 = "        aFelly = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "    revise.routines = revise.closing[(\"c\"+\"hD\"+\"rA\"+(\"oxidation\",\"proportion\",\"walrus\",\"t\")).replace(\"D\", CDDSSF" ascii
    $s18 = "        BtUsyenX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s19 = "        BtUsyenX = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s20 = " across the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii

  condition:
    uint16(0) == 0x4379 and
    8 of them
}