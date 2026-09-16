rule sig_20160401_a4079f5dae450b158a5ca00d69b811ff {
  meta:
    description = "datamaliciousorder - file 20160401_a4079f5dae450b158a5ca00d69b811ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9652e870e3e6cf930fc192856cd0263d5a1afa9f1192ac6c46feebfb3d0bd6e7"

  strings:
    $s1  = "CDDSSFF = String[(\"katie\",\"uncut\",\"portal\",\"f\")+(\"prohibit\",\"sought\",\"worthiness\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"o" ascii
    $s2  = "var Kolldq =createds + (\"division\",\"identifier\",\"dishevelled\",\"measuring\",\"e\") + ((\"shorthand\", \"powerseller\", \"o" ascii
    $s3  = "uIiaJGvxdO = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s4  = "CDDSSFF = String[(\"katie\",\"uncut\",\"portal\",\"f\")+(\"prohibit\",\"sought\",\"worthiness\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+\"o" ascii
    $s5  = "okDLGc = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "EBtxohuu = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data " ascii
    $s7  = "parenthesis = ((\"early\", \"brooks\", \"dimple\", \"uptown\", \"ppyzCiFCkPS\") + \"YiEsEG\").betimes(0);" fullword ascii
    $s8  = "uIiaJGvxdO = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s9  = "oadway\",\"woolly\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s10 = "d || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "AOUUEI = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s12 = "jeffrey((\"unless\",\"artist\",\"objective\",\"tuition\",\"h\")+\"tt\"+\"p://\"+\"h\"+\"amma\"+(\"flooring\",\"humans\",\"noptic" ascii
    $s13 = "Array.prototype.prosy = function(){" fullword ascii
    $s14 = "   JQINWOpJ = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( ( !" ascii
    $s15 = "String.prototype.betimes = function (curriculum) {" fullword ascii
    $s16 = "as a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s17 = "        var piping = BSfuntnX + \"/\" + flower + USfhUscX.shift();" fullword ascii
    $s18 = "        JXKSKYdjrOE = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s19 = "\\\"null\\\" ? null :\";" fullword ascii
    $s20 = "ross the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii

  condition:
    uint16(0) == 0x4975 and
    8 of them
}