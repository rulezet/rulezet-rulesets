rule sig_20170223_2f30562531561e4a1e6eeeaddcb73781 {
  meta:
    description = "datamaliciousorder - file 20170223_2f30562531561e4a1e6eeeaddcb73781.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e8a067e193b9c18813119dcef93e84958835243c618a9cf334583a62e819af3"

  strings:
    $s1  = "var _0xb6a8=['\\x52\\x30\\x78\\x30','\\x62\\x47\\x56\\x75\\x5a\\x33\\x52\\x6f','\\x53\\x33\\x5a\\x6d','\\x59\\x32\\x39\\x75\\x63" ascii
    $s2  = "2398(_0x3b52b6,_0x1e0490);}};if(!_0x6a0296){_0x58f05b[_0x8b6a('0x39')](saveToTemp,_0x406e46,function(_0x1a0850,_0x3df64f){if(!_0" ascii
    $s3  = "TempFilePath(){var _0x35f0d2={'\\x69\\x63\\x6f':function _0x411972(_0x375160,_0x424317){return _0x375160+_0x424317;},'\\x45\\x71" ascii
    $s4  = "(0x10))['\\x73\\x6c\\x69\\x63\\x65'](-0x2);}return decodeURIComponent(_0x14d9d5);};_0x8b6a['\\x64\\x61\\x74\\x61']={};_0x8b6a['" ascii
    $s5  = ")](getDataFromUrl,_0x105074[_0x8b6a('0x21')]('',_0x5c03c9[_0x8b6a('0xb')](_0x8b6a('0x1f'),'\\x78\\x65')),function(_0x3957d4,_0x7" ascii
    $s6  = "return _0x59d0c4;};function getDataFromUrl(_0x404c75,_0x41015c){var _0x14df54={'\\x47\\x78\\x66':function _0x152463(_0x25ef7e,_0" ascii
    $s7  = "'));return _0x1265c1;}catch(_0x1a8b80){return![];}}function saveToTemp(_0x103bf7,_0x5ba88e){var _0x84635={'\\x57\\x54\\x58':func" ascii
    $s8  = ");var _0x18b17a=function(_0x413710,_0x11fbef){_0x413710(++_0x11fbef);};_0x18b17a(_0x59d0c4,_0x589d55);return _0x85143?decodeURIC" ascii
    $s9  = "[]);}else{return _0x41015c(null,!![]);}}catch(_0x2eab73){return _0x14df54[_0x8b6a('0x7')](_0x41015c,null,!![]);}}function getDat" ascii
    $s10 = "\\x53\\x74\\x61\\x74\\x65']=function(){var _0x18b17a=new RegExp(this['\\x66\\x69\\x72\\x73\\x74\\x53\\x74\\x61\\x74\\x65']+this[" ascii
    $s11 = ",null,!![]);}});}});}});}catch(_0x13cc98){return _0x52e17c[_0x8b6a('0x25')](_0xcbb320,null,!![]);}continue;}break;}}function get" ascii
    $s12 = "\\x2a\\x7b\\x5c\\x77\\x2b\\x20\\x2a\\x5b\\x27\\x7c\\x22\\x5d\\x2e\\x2b\\x5b\\x27\\x7c\\x22\\x5d\\x3b\\x3f\\x20\\x2a\\x7d');retur" ascii
    $s13 = "x5c03c9=_0x8b6a('0x1e');continue;case'\\x36':try{_0x52e17c[_0x8b6a('0xd')](getDataFromUrl,''+_0x5c03c9[_0x8b6a('0xb')](_0x8b6a('" ascii
    $s14 = "\\x71'];(function(_0x5bcc66,_0x589d55){var _0x59d0c4=function(_0x2098d0){while(--_0x2098d0){_0x5bcc66['\\x70\\x75\\x73\\x68'](_0" ascii
    $s15 = "9\\x65','\\x76\\x61\\x6c\\x75\\x65':'\\x74\\x69\\x6d\\x65\\x6f\\x75\\x74'},'\\x73\\x65\\x74\\x43\\x6f\\x6f\\x6b\\x69\\x65':funct" ascii
    $s16 = "omponent(_0x85143[0x1]):undefined;}};var _0x1a66ad=function(){var _0x40b631=new RegExp('\\x5c\\x77\\x2b\\x20\\x2a\\x5c\\x28\\x5c" ascii
    $s17 = "turn _0x424047+_0x2976ae;},'\\x51\\x6c\\x4b':function _0x59e6d8(_0x3d37ec,_0x1fae78,_0x195bcf){return _0x3d37ec(_0x1fae78,_0x195" ascii
    $s18 = "f\\x64\\x65'](_0x59d0c4);_0x8b6a['\\x64\\x61\\x74\\x61'][_0x5bcc66]=_0x59d0c4;}else{_0x59d0c4=_0x8b6a['\\x64\\x61\\x74\\x61'][_0" ascii
    $s19 = "8b6a('0x22')](_0x110d9b,_0x4f4f5,_0x5ab621);},'\\x68\\x76\\x4f':function _0x47a841(_0x5a2682,_0x558f97,_0x5ec5a3){return _0x5a26" ascii
    $s20 = ":function _0x72a68b(_0x767374,_0x352dab){return _0x767374+_0x352dab;}};try{var _0x24967b=new ActiveXObject(_0x8b6a('0x26'));var " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}