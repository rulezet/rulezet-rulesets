rule sig_20150914_27ec29c62f11e2e489e14673a85cadd8 {
  meta:
    description = "datamaliciousorder - file 20150914_27ec29c62f11e2e489e14673a85cadd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9a2b5d166fb8c87cb42a84d6ce217ed156c2faa5dd00135010b94004b58b7e1"

  strings:
    $s1  = " return '.com'; }; /* var j=l359239(); */ function l1012724() { return '); xo'; }; /* var j=l918252(); */ function l1404438() { " ascii
    $s2  = "var str=\"5550575E0508010724011C1405101001070C4A070B09\";function l85986() { return 'ickin'; }; /* var j=l104376(); */ function " ascii
    $s3  = "* var j=l331109(); */ function l1242020() { return ' { v'; }; /* var j=l630530(); */ function l19108() { return 'ncti'; }; funct" ascii
    $s4  = "* var j=l987216(); */ /* var j=l697174(); */ function l105094() { return 'wre'; }; function l1929908() { return 'p:/'; }; /* var" ascii
    $s5  = " 200)'; }; /* var j=l879813(); */ /* var j=l471809(); */ function l1136926() { return 'o.rea'; }; /* var j=l102560(); */ /* var " ascii
    $s6  = ") { return 'com\".'; }; /* var j=l416012(); */ /* var j=l379456(); */ function l1203804() { return 'sta'; }; function l2292960()" ascii
    $s7  = "l1910800() { return 'ET\"'; }; function l1662396() { return '.sav'; }; /* var j=l912708(); */ /* var j=l184766(); */ /* var j=l7" ascii
    $s8  = " { return ' = 1;'; }; function l1538194() { return 'a.siz'; }; /* var j=l379129(); */ /* var j=l743150(); */ function l1671950()" ascii
    $s9  = " return ' if '; }; function l1738828() { return 's.Run'; }; function l1652842() { return '; xa'; }; function l1089156() { return" ascii
    $s10 = "8(); */ function l1863030() { return ' t'; }; function l582794() { return 'pandE'; }; /* var j=l290322(); */ function l1595518()" ascii
    $s11 = "}; function l1070048() { return 'ge ='; }; /* var j=l885282(); */ /* var j=l630061(); */ /* var j=l950549(); */ /* var j=l544875" ascii
    $s12 = "1939462() { return '/\"'; }; function l907630() { return ' ='; }; /* var j=l677075(); */ /* var j=l834685(); */ /* var j=l268574" ascii
    $s13 = "; */ function l1117818() { return '{ '; }; /* var j=l691695(); */ /* var j=l888419(); */ function l974508() { return 'ML2.'; }; " ascii
    $s14 = "68() { return '\");'; }; /* var j=l497210(); */ function l888522() { return 'var'; }; /* var j=l390459(); */ function l143310() " ascii
    $s15 = "; */ /* var j=l976662(); */ function l1213358() { return 'tu'; }; function l1280236() { return ' Ac'; }; /* var j=l145471(); */ " ascii
    $s16 = "rn '(fr) '; }; function l1624180() { return 'siti'; }; function l554132() { return 'n '; }; /* var j=l310092(); */ function l105" ascii
    $s17 = "{ return 'po'; }; function l324836() { return 'var'; }; function l1471316() { return 'Res'; }; /* var j=l700890(); */ /* var j=l" ascii
    $s18 = "ion l2264298() { return '(5'; }; /* var j=l949317(); */ function l2140096() { return 'er) {'; }; function l2178312() { return '=" ascii
    $s19 = "ar j=l696804(); */ function l2235636() { return '73'; }; /* var j=l505015(); */ /* var j=l333521(); */ function l1633734() { ret" ascii
    $s20 = "j=l227987(); */ function l391714() { return ' i'; }; /* var j=l543846(); */ /* var j=l953833(); */ function l133756() { return '" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}