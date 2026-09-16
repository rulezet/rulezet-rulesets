rule _20160405_1c85489f6d2b3b7ed9309692001a9ff2_20160405_ef0513632706_551 {
  meta:
    description = "datamaliciousorder - from files 20160405_1c85489f6d2b3b7ed9309692001a9ff2.js, 20160405_ef05136327063922a6e9d925a52c6d65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f34139632a80f72bce3a35d433acd74729a59ca4319aaf0bfd24c7fe5ab9b98c"
    hash2       = "e0a4dc435556b426b78c5f962203dc532652b723ddd21e9a38db71aa38a3b615"

  strings:
    $s1  = "f you attempt to set expando properties noData: { \\\"applet \\\": true, \\\"embed \\\": true,\";" fullword ascii
    $s2  = "var sponsor1 = 7*2*7 + sponsor;" fullword ascii
    $s3  = "String.prototype.tussle = function () {" fullword ascii
    $s4  = "ando ]; return !!elem && !isEmptyDataObject( elem ); },\";" fullword ascii
    $s5  = "function batch(susanna, overcome) {" fullword ascii
    $s6  = "String.prototype.disengage = function () {" fullword ascii
    $s7  = "false */ } else if ( support.deleteExpando || cache != cache.window ) { /* jshint eqeqeq: true */ delete cache[ id ];\";" fullword ascii
    $s8  = "        var sleek = losing + \"/\" + overcome + filing.shift();" fullword ascii
    $s9  = "zhCQsLHgt = \"} If there is no data left in the cache, we want to continue and let the cache object itself get destroyed if ( pv" ascii
    $s10 = "    jPwIna = \"jQuery.fn.extend( { data: function( key, value ) { var i, name, data, elem = this[ 0 ], attrs = elem && elem.attr" ascii
    $s11 = "zhCQsLHgt = \"} If there is no data left in the cache, we want to continue and let the cache object itself get destroyed if ( pv" ascii
    $s12 = "    jPwIna = \"jQuery.fn.extend( { data: function( key, value ) { var i, name, data, elem = this[ 0 ], attrs = elem && elem.attr" ascii
    $s13 = "var hermitage = this[filing.shift()];" fullword ascii
    $s14 = ") { return internalRemoveData( elem, name, true ); } } );\";" fullword ascii
    $s15 = "oexzMPAXAdf = \"} i = name.length; while ( i-- ) { delete thisCache[ name[ i ] ]; \";" fullword ascii
    $s16 = "var losing = blockhouse[filing.shift()](filing.shift());" fullword ascii
    $s17 = "var blockhouse = new hermitage(cronies[1]);" fullword ascii
    $s18 = "var sponsor = 0;" fullword ascii
    $s19 = "UHeqUCNgja = \"} See jQuery.data for more information if ( !pvt ) { delete cache[ id ].data;\";" fullword ascii
    $s20 = "var clove = new hermitage(cronies[0]);" fullword ascii

  condition:
    (uint16(0) == 0x656f and (8 of them)
    ) or (all of them)
}