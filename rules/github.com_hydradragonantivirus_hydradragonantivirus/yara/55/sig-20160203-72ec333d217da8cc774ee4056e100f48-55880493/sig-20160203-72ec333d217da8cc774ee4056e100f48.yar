rule sig_20160203_72ec333d217da8cc774ee4056e100f48 {
  meta:
    description = "datamaliciousorder - file 20160203_72ec333d217da8cc774ee4056e100f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e549c9e2860d522742de094d6daef6b5387cd87ba94eca4cd51ff295c6ee1f21"

  strings:
    $s1  = "u', 'T'.split(\"\").reverse().join(\"\")) + '' , arguments[0], false);" fullword ascii
    $s2  = " + ('AO', 'hqI', 'YH6yok', 'g') + 's']('%TE' + ('lhk3BU', 'oL', 'iF6w', 'M'.split(\"\").reverse().join(\"\")) + 'P%' ) + String " ascii
    $s3  = "D', 'g') + 'e'] = function() {" fullword ascii
    $s4  = "function awxSqEHgO () {" fullword ascii
    $s5  = "            var aI2HWwx9O = new this['A' + ('Hwl', 'dY5yZh', '0PQm', 'c') + 't' + ('JrQ', 'f0UR', 'v35', 'i') + 'v' + ('M7F', 'k" ascii
    $s6  = "    var amilaSBgQ = new this['A' + ('qyvr', 'FzaDG3', 'q6Lq7', 'c') + '' + ('UBUB', 'PKr7', 'xGT6', 't') + '' + ('0SU', 'wB', 'g" ascii
    $s7  = "            var aI2HWwx9O = new this['A' + ('Hwl', 'dY5yZh', '0PQm', 'c') + 't' + ('JrQ', 'f0UR', 'v35', 'i') + 'v' + ('M7F', 'k" ascii
    $s8  = "    var aqc84UoSc = new this['A' + ('Ky', 'tAyq65', 'Vpa5', 'c') + 't' + ('z9xgv', 'RgkF', 'tPE', 'i') + '' + ('cl4N', 'uTY4Po'," ascii
    $s9  = "        amilaSBgQ['o' + ('7XO', '1M1AA', 'yQ', 'p') + 'e' + ('Axv7LD', 'Kk', 'VsSmSY', 'n') + '']('GE' + ('yFXkHx', 'M5LEYm', 'u" ascii
    $s10 = "    var amilaSBgQ = new this['A' + ('qyvr', 'FzaDG3', 'q6Lq7', 'c') + '' + ('UBUB', 'PKr7', 'xGT6', 't') + '' + ('0SU', 'wB', 'g" ascii
    $s11 = "    var aqc84UoSc = new this['A' + ('Ky', 'tAyq65', 'Vpa5', 'c') + 't' + ('z9xgv', 'RgkF', 'tPE', 'i') + '' + ('cl4N', 'uTY4Po'," ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}