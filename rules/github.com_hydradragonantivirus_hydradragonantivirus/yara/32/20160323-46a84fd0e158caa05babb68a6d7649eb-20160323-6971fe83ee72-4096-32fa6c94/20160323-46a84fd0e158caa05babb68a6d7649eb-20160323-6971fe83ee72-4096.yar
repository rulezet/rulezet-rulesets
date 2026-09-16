rule _20160323_46a84fd0e158caa05babb68a6d7649eb_20160323_6971fe83ee72_4096 {
  meta:
    description = "datamaliciousorder - from files 20160323_46a84fd0e158caa05babb68a6d7649eb.js, 20160323_6971fe83ee7210b325f66a9464a32151.js, 20160324_5394cc30ec31bb5a9836a16b86cd13fc.js, 20160324_d37a356748219f60472be1891614ca37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c2c2e5bf99ec7d409959b8a18811f1998f85a266f8283f61ea26ade2dd0b71a"
    hash2       = "c818fc3b80050400dffcbf39bd7eb16e825197174193880ad537a17864790caf"
    hash3       = "bf5d9f2a5d6c3ff4313aa9d74a005f480bf28ebd75ecb4d79f1ea78d7d0cd478"
    hash4       = "474ebc307396ac34363bb5e151d1461ade3518c60a1c35892fb621932f07b7b6"

  strings:
    $s1 = "m ) { return siblings( elem.firstChild ); }, contents: function( elem ) { return jQuery.nodeName( elem, \\\"iframe\\\" ) ? elem." ascii
    $s2 = "entDocument || elem.contentWindow.document : jQuery.merge( [], elem.childNodes ); } }, function( name, fn ) { jQuery.fn[ name ] " ascii
    $s3 = "= function( until, selector ) { var ret = jQuery.map( this, fn, until );\";" fullword ascii
    $s4 = "return dir( elem, \\\"nextSibling\\\", until ); }, prevUntil: function( elem, i, until ) { return dir( elem, \\\"previousSibling" ascii
    $s5 = "til ); }, siblings: function( elem ) { return siblings( ( elem.parentNode || {} ).firstChild, elem ); }, children: function( ele" ascii

  condition:
    (uint16(0) == 0x4555 and (all of them)
    ) or (all of them)
}