rule sig_196961339_5R_20190420 {
  meta:
    description = "datamaliciousorder - file 196961339-5R-20190420.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "474b7f305055ff40e7d644828c8bb5b3b19bdc17a8a6054c88ce7489a80314f3"

  strings:
    $s1  = "0c87 += String['fromCharCode'](0xff & _0x363bd0 >> (-0x2 * _0x6b5c9c & 0x6)) : 0x0) {" fullword ascii
    $s2  = "                for (var _0x6b5c9c = 0x0, _0x363bd0, _0x1ca020, _0x533c90 = 0x0, _0x540c87 = ''; _0x1ca020 = _0x2bdb14['charAt']" ascii
    $s3  = "5'], function (_0x718543, _0xae187c) {" fullword ascii
    $s4  = "function _0x45fe80() {" fullword ascii
    $s5  = "(function (_0x1200d4, _0x4db602) {" fullword ascii
    $s6  = "function _0x330744(_0x43f78a, _0x537225) {" fullword ascii
    $s7  = "function _0x17c9fb(_0x41ec83, _0xd58d2c) {" fullword ascii
    $s8  = "var _0x42f8 = function (_0xb9df60, _0x255be6) {" fullword ascii
    $s9  = "            Res = WshShell[_0x42f8('0x6e', '\\x74\\x47\\x73\\x46')](Text, 0x0, Title, _0x4be589[_0x42f8('0x6f', '\\x48\\x25\\x33" ascii
    $s10 = "function _0x30c9e6(_0x426028) {" fullword ascii
    $s11 = "            Res = WshShell[_0x42f8('0x6e', '\\x74\\x47\\x73\\x46')](Text, 0x0, Title, _0x4be589[_0x42f8('0x6f', '\\x48\\x25\\x33" ascii
    $s12 = "_0x467733(function (_0xd2352b, _0xa2e353) {" fullword ascii
    $s13 = "                var _0x29e515 = Function('return\\x20(function()\\x20' + '{}.constructor(\\x22return\\x20this\\x22)(\\x20)' + ')" ascii
    $s14 = "                _0x5550ab += String['fromCharCode'](_0x391284['charCodeAt'](_0x5e2cef) ^ _0x15e06e[(_0x15e06e[_0x27fc87] + _0x15" ascii
    $s15 = "        return _0x16d63c + _0x731fbb;" fullword ascii
    $s16 = "                _0x5550ab += String['fromCharCode'](_0x391284['charCodeAt'](_0x5e2cef) ^ _0x15e06e[(_0x15e06e[_0x27fc87] + _0x15" ascii
    $s17 = "        return _0x27360f + _0x21b92c;" fullword ascii
    $s18 = "        return _0x2f23da + _0x36becb;" fullword ascii
    $s19 = "        var _0x16bece = _0xb6dc55[_0x42f8('0x44', '\\x55\\x5a\\x6f\\x24')]('\\x5c' + Math['\\x72\\x61\\x6e\\x64\\x6f\\x6d']()[_0" ascii
    $s20 = "        var _0x16bece = _0xb6dc55[_0x42f8('0x44', '\\x55\\x5a\\x6f\\x24')]('\\x5c' + Math['\\x72\\x61\\x6e\\x64\\x6f\\x6d']()[_0" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}