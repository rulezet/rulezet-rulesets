rule sig_20160516_f9f2e4ce08e09f4f9e78761d8d56f472 {
  meta:
    description = "datamaliciousorder - file 20160516_f9f2e4ce08e09f4f9e78761d8d56f472.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "179e7ba8bf3231a58b7832c3ca74f5669b19943f6335cbeb88a8cdc7c2783b1e"

  strings:
    $s1  = "agent(\"aHR0cDovLw==\".whirring4()+\"\\u0064\\u0069\\u0067\\u0061\\u0073\\u0069\\u0062\\u002E\\u0063\\u006F\"+\"\\u006D\\u002F" ascii
    $s2  = "function agent(alerts, forests) {" fullword ascii
    $s3  = "agent(\"aHR0cDovLw==\".whirring4()+\"\\u0064\\u0069\\u0067\\u0061\\u0073\\u0069\\u0062\\u002E\\u0063\\u006F\"+\"\\u006D\\u002F" ascii
    $s4  = "booth = booth+ favor.shift();" fullword ascii
    $s5  = "weasel = ((\"lightweight\", \"inefficient\", \"orgasm\", \"vestige\", \"EIwULtsBtBkp\") + \"WGjiNWAlbFV\").whirring2();" fullword ascii
    $s6  = "var configuring = new aluminum(nikon[0]);" fullword ascii
    $s7  = "String.prototype.whirring4 = function() {" fullword ascii
    $s8  = "String.prototype.whirring2 = function () {" fullword ascii
    $s9  = "String.prototype.whirring = function () {" fullword ascii
    $s10 = "var smooth = 6/6;" fullword ascii
    $s11 = "investigate = this;" fullword ascii
    $s12 = "var journalism =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".whirring4();" fullword ascii
    $s13 = "var impair = 0;" fullword ascii
    $s14 = "lerts, false);" fullword ascii
    $s15 = "var sampson = new aluminum(nikon[1]);" fullword ascii
    $s16 = "for (var i in acdbentity){investigate = investigate.replace(i, acdbentity[i]);}" fullword ascii
    $s17 = "var exceptionally = \"QWN0aXZlWE9iamVjdA==\".whirring4();" fullword ascii
    $s18 = "sampson[favor.shift()](booth, smooth, true);ztHlwAOQRr = \"_F17_\";" fullword ascii
    $s19 = "var thing = sampson[favor.shift()](favor.shift());" fullword ascii
    $s20 = "var aluminum = this[favor.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}