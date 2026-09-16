rule sig_20160401_b0f1bf22e1b486ffdebdba886583ae28 {
  meta:
    description = "datamaliciousorder - file 20160401_b0f1bf22e1b486ffdebdba886583ae28.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75b4efa86b47447afc99253784af251a6e328f6647066b1bc315f1de847c3f20"

  strings:
    $s1  = "CDDSSFF = String[(\"ashley\",\"participate\",\"recognized\",\"f\")+(\"juvenile\",\"pianoforte\",\"severn\",\"ro\")+\"mC\"+\"ha\"" ascii
    $s2  = "var Kolldq =linkings + (\"distraction\",\"osiris\",\"inlet\",\"saddled\",\"e\") + ((\"importune\", \"emanuel\", \"skylight\", \"" ascii
    $s3  = "IRYCeEuRbB = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s4  = "Array.prototype.remote = function(){" fullword ascii
    $s5  = "jGoowj = \" data = elem.getAttribute( name );\";" fullword ascii
    $s6  = "IRYCeEuRbB = \" If nothing was found internally, try to fetch any data from the HTML5 data-* attribute if ( data === undefined &" ascii
    $s7  = "YuuCpWjErk = \" Only convert to a number if it doesn\\\"t change the string +data + \\\"\\\" === data ? +data : rbrace.test( dat" ascii
    $s8  = "\",\"outlawed\",\"T\"), \"\" + stark, \"krASNzcbnv\" === \"hnenbMtt\");" fullword ascii
    $s9  = "!id || !cache[ id ] || ( !pvt && !cache[ id ].data ) ) && data === undefined && typeof name === \\\"string\\\" ) { return; \";" fullword ascii
    $s10 = "   jWCltHlQqu = \" Avoid doing any more work than we need to when trying to get data on an object that has no data at all if ( (" ascii
    $s11 = "wYgWcRd = \" var name = \\\"data-\\\" + key.replace( rmultiDash, \\\"-$1\\\" ).toLowerCase();\";" fullword ascii
    $s12 = "var Kolldq =linkings + (\"distraction\",\"osiris\",\"inlet\",\"saddled\",\"e\") + ((\"importune\", \"emanuel\", \"skylight\", \"" ascii
    $s13 = " a DOM node with no cache id = isNode ? elem[ internalKey ] : elem[ internalKey ] && internalKey;\";" fullword ascii
    $s14 = "        btWNrpRWASI = \"} Make sure we set the data so it isn\\\"t changed later jQuery.data( elem, key, data );\";" fullword ascii
    $s15 = "\\\"null\\\" ? null :\";" fullword ascii
    $s16 = "        aFHmAfyv = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s17 = "        aFHmAfyv = \" if the public data object is empty, the private is still empty if ( name === \\\"data\\\" && jQuery.isEmpt" ascii
    $s18 = "cross the DOM-JS boundary isNode = elem.nodeType,\";" fullword ascii
    $s19 = "ct( obj[ name ] ) ) { continue; } if ( name !== \\\"toJSON\\\" ) { return false; } \";" fullword ascii
    $s20 = "en\", \"nwHMpLdEi\") + \"AocYoqu\").sophisticated(mounted) + ((\"rancour\", \"intoxicating\", \"madeline\", \"relevant\", \"stak" ascii

  condition:
    uint16(0) == 0x5249 and
    8 of them
}