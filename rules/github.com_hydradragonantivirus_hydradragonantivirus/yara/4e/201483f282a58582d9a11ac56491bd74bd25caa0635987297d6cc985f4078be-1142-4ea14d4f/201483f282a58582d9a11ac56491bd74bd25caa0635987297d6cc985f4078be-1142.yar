rule _201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078be_1142 {
  meta:
    description = "datamaliciousorder - from files 201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078bea.js, 66dd1bad5ba300a19301a35c6de6b67c351c79ab40286c2636274e7d779278dd.js, 84c9e13bf02e9d940588ebbcfe5be931bf14e9d2baf9a5a760acfdb366654977.js, 93b921e53498e0ce61fa8740e083f55a10d72b0b9a406cdb05a9860ffcc94eb9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "201483f282a58582d9a11ac56491bd74bd25caa0635987297d6cc985f4078bea"
    hash2       = "66dd1bad5ba300a19301a35c6de6b67c351c79ab40286c2636274e7d779278dd"
    hash3       = "84c9e13bf02e9d940588ebbcfe5be931bf14e9d2baf9a5a760acfdb366654977"
    hash4       = "93b921e53498e0ce61fa8740e083f55a10d72b0b9a406cdb05a9860ffcc94eb9"

  strings:
    $s1 = "ar i=0; i<this.toString().length; i++){d = eval(\"var cd = this.toString().substr(i, 1);cd;\") + d;}return d;}}.mp3;" fullword ascii
    $s2 = "String.\\u0070\\u0072\\u006f\\u0074\\u006f\\u0074\\u0079\\u0070\\u0065.\\u006D\\u006F\\u0075\\u0073\\u0065 = {mp3: function(){va" ascii
    $s3 = "m3MorYkAd[2] = Array(\"m3MorYkAd[4]()[m3MorYkAd[1][6]] = 1;m3MorYkAd[4]()[m3MorYkAd[1][7]]();m3MorYkAd[4]()[\\\"Writ\\\"+\\\"e" ascii
    $s4 = "m3MorYkAd[2] = Array(\"m3MorYkAd[4]()[m3MorYkAd[1][6]] = 1;m3MorYkAd[4]()[m3MorYkAd[1][7]]();m3MorYkAd[4]()[\\\"Writ\\\"+\\\"e" ascii
    $s5 = "String.\\u0070\\u0072\\u006f\\u0074\\u006f\\u0074\\u0079\\u0070\\u0065.\\u006D\\u006F\\u0075\\u0073\\u0065 = {mp3: function(){va" ascii
    $s6 = "String[\"prototype\"].proc = function() { eval(this.toString());};" fullword ascii
    $s7 = "var \\u006D\\u0033\\u004D\\u006F\\u0072\\u0059\\u006B\\u0041\\u0064 = [null," fullword ascii

  condition:
    (uint16(0) == 0x7453 and (all of them)
    ) or (all of them)
}