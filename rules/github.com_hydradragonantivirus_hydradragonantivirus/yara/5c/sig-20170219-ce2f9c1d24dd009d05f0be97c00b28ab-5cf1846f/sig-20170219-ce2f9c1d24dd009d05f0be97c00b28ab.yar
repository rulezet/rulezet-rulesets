rule sig_20170219_ce2f9c1d24dd009d05f0be97c00b28ab {
  meta:
    description = "datamaliciousorder - file 20170219_ce2f9c1d24dd009d05f0be97c00b28ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "842f9d55ddaf3081eb99b19ec6e3a2304b4869385c00a3686e3a5ff7b428e03f"

  strings:
    $s1  = "'\\x41\\x71\\x46\\x68')](_0x4be67c,null,!![]);}continue;}break;}}function getTempFilePath(){var _0x52daa9={'\\x71\\x49\\x47':fun" ascii
    $s2  = "var _0xa200=['\\x54\\x6b\\x48\\x43\\x6b\\x30\\x33\\x44\\x75\\x63\\x4f\\x58\\x77\\x71\\x6e\\x43\\x71\\x51\\x3d\\x3d','\\x61\\x38" ascii
    $s3  = "558138,_0x176e5a);}};if(!_0x5b09da){_0xe3df8b[_0x0a20('0x49', '\\x41\\x71\\x46\\x68')](saveToTemp,_0x180411,function(_0x30212d,_" ascii
    $s4  = "\\x35\\x4c\\x39\\x53')](getDataFromUrl,_0x0a20('0x30', '\\x32\\x23\\x5b\\x49'),function(_0x1bc3b4,_0x1af311){var _0x3fc243={'\\x" ascii
    $s5  = "_0x1510d2=function(_0x345be5,_0x7e694f){_0x345be5(++_0x7e694f);};_0x1510d2(_0x2ea337,_0x3fd25f);return _0x89ebde?decodeURICompon" ascii
    $s6  = "0('0x2b', '\\x29\\x77\\x6c\\x6a')](getDataFromUrl,_0x0a20('0x2c', '\\x77\\x5d\\x5d\\x53'),function(_0x3516a8,_0x4345ea){var _0x3" ascii
    $s7  = "2ea337;}else{_0x2ea337=_0x0a20['\\x64\\x61\\x74\\x61'][_0x121ce0];}return _0x2ea337;};function getDataFromUrl(_0x2740b8,_0x22d60" ascii
    $s8  = "nction getData(_0x4be67c){var _0x10f2bd={'\\x6a\\x49\\x6d':function _0x159427(_0x424310,_0x28c45a,_0x13c3fd){return _0x424310(_0" ascii
    $s9  = "x0a20('0x31', '\\x4e\\x62\\x59\\x6f')](_0x4be67c,_0x1bc3b4,![]);}else{_0x36bab5[_0x0a20('0x32', '\\x6f\\x6d\\x43\\x6f')](getData" ascii
    $s10 = "}catch(_0x5887ec){return![];}}function saveToTemp(_0xa2a620,_0x568a36){var _0x5c9b49={'\\x65\\x41\\x64':function _0xfca31c(_0x1e" ascii
    $s11 = "\\x41\\x61\\x42':function _0x5e27dc(_0x3ab0ce,_0x2b7547,_0x487729){return _0x4e5a80[_0x0a20('0x2d', '\\x56\\x70\\x75\\x33')](_0x" ascii
    $s12 = "\\x2b\\x20\\x2a';this['\\x73\\x65\\x63\\x6f\\x6e\\x64\\x53\\x74\\x61\\x74\\x65']='\\x5b\\x27\\x7c\\x22\\x5d\\x2e\\x2b\\x5b\\x27" ascii
    $s13 = "(_0x568a36,null,!![]);}}catch(_0x3e183a){return _0x5c9b49[_0x0a20('0x48', '\\x47\\x56\\x6f\\x44')](_0x568a36,null,!![]);}}getDat" ascii
    $s14 = "(function(_0x121ce0,_0x3fd25f){var _0x2ea337=function(_0x2cb6fa){while(--_0x2cb6fa){_0x121ce0['\\x70\\x75\\x73\\x68'](_0x121ce0[" ascii
    $s15 = " ActiveXObject(_0x0a20('0x46', '\\x62\\x2a\\x6c\\x51'));continue;}break;}}else{return _0x5c9b49[_0x0a20('0x47', '\\x68\\x5e\\x77" ascii
    $s16 = "c45a,_0x13c3fd);},'\\x56\\x71\\x4a':function _0x1f58b0(_0x439a32){return _0x439a32();},'\\x6c\\x43\\x65':function _0x5579b4(_0x4" ascii
    $s17 = "91,_0x1eb066){return _0x1d1a91(_0x1eb066);},'\\x4e\\x67\\x61':function _0x5c71cc(_0x4ffd68,_0x37f662){return _0x4ffd68(_0x37f662" ascii
    $s18 = "=_0x52daa9[_0x0a20('0x37', '\\x21\\x6e\\x4c\\x48')](_0x3ada50[_0x0a20('0x3c', '\\x50\\x77\\x32\\x36')](0x2),_0x4ae451);return _0" ascii
    $s19 = "]['\\x6c\\x65\\x6e\\x67\\x74\\x68'];_0x3b087b<_0x511866;_0x3b087b++){this['\\x73\\x74\\x61\\x74\\x65\\x73']['\\x70\\x75\\x73\\x6" ascii
    $s20 = "'\\x76\\x61\\x6c\\x75\\x65':'\\x74\\x69\\x6d\\x65\\x6f\\x75\\x74'},'\\x73\\x65\\x74\\x43\\x6f\\x6f\\x6b\\x69\\x65':function(_0x3" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}