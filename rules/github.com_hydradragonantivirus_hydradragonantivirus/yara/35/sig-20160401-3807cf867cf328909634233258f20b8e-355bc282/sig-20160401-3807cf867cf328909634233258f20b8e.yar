rule sig_20160401_3807cf867cf328909634233258f20b8e {
  meta:
    description = "datamaliciousorder - file 20160401_3807cf867cf328909634233258f20b8e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90b20e2f00f4623203bf52d57bf52c4f848a0324f4a00c9e2aeab75a0be6b8db"

  strings:
    $s1  = "CDDSSFF = String[(\"ratio\",\"ignominious\",\"decrease\",\"f\")+(\"split\",\"seaside\",\"growth\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s2  = "BItPyuIdF = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s3  = "BItPyuIdF = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &&" ascii
    $s4  = "QgJuzcd = \" data = elem.getAttribute( name );\";" fullword ascii
    $s5  = "flagon = ((\"solid\", \"sonny\", \"theories\", \"feeder\", \"puSQHqCIbcUq\") + \"LyRVnyk\").segment(0);" fullword ascii
    $s6  = "CDDSSFF = String[(\"ratio\",\"ignominious\",\"decrease\",\"f\")+(\"split\",\"seaside\",\"growth\",\"ro\")+\"mC\"+\"ha\"+\"rC\"+" ascii
    $s7  = "var Kolldq =reflects + (\"centers\",\"teens\",\"roland\",\"interesting\",\"e\") + ((\"aliment\", \"banners\", \"corkscrew\", \"m" ascii
    $s8  = "lVpWgv = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( data ) " ascii
    $s9  = "e\", \"nwHMpLdEi\") + \"AocYoqu\").segment(charger) + ((\"whooping\", \"copiously\", \"viewer\", \"gently\", \"pennies\", \"dnTi" ascii
    $s10 = " !id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s11 = "jJSNgzw = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s12 = "   GyeShusMObG = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( " ascii
    $s13 = "String.prototype.segment = function (collection) {" fullword ascii
    $s14 = "Array.prototype.thered = function(){" fullword ascii
    $s15 = "s a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s16 = "        IPdGOEVEEBE = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s17 = "        qOlWwSVrxr = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEm" ascii
    $s18 = "        qOlWwSVrxr = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEm" ascii
    $s19 = "nENTdV = \"} return data; \";" fullword ascii
    $s20 = "oss the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii

  condition:
    uint16(0) == 0x4942 and
    8 of them
}