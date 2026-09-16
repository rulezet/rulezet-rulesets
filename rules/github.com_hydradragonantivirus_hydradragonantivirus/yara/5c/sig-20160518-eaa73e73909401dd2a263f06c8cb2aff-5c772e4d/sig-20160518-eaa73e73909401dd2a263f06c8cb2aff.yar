rule sig_20160518_eaa73e73909401dd2a263f06c8cb2aff {
  meta:
    description = "datamaliciousorder - file 20160518_eaa73e73909401dd2a263f06c8cb2aff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e2a25c34207f37e48d314c251b3d7ce3674d081a4f469230a7b000d2853e264"

  strings:
    $s1  = "executive(\"aHR0cDovLw==\".sausage4()+\"\\u0069\\u006B\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\\u0077\\u007A\"+\"\\u002" ascii
    $s2  = "var rebecca = [librarian, wayside,punch,  \"\"+\".\"+(\"wednesday\",\"selfmade\",\"merge\",\"peking\",\"conspiracy\",\"sample\"," ascii
    $s3  = "executive(\"aHR0cDovLw==\".sausage4()+\"\\u0069\\u006B\\u0073\\u0074\\u0075\\u0064\\u0069\\u006F\\u002E\\u0077\\u007A\"+\"\\u002" ascii
    $s4  = "var locally=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sausage4())&&predatory[\"c3RhdHVz\".sausage4()] +\"\"==\"MjAw\".saus" ascii
    $s5  = "for (var i in injection){designer = designer.replace(i, injection[i]);}" fullword ascii
    $s6  = "var locally=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sausage4())&&predatory[\"c3RhdHVz\".sausage4()] +\"\"==\"MjAw\".saus" ascii
    $s7  = "var injection = {" fullword ascii
    $s8  = "chronic = ((\"emblematic\", \"turret\", \"unbidden\", \"versus\", \"sAPBPFuFmW\") + \"AnNLUIVTeyp\").sausage2();" fullword ascii
    $s9  = "dispersion = ((\"lurch\", \"whiten\", \"video\", \"persian\", \"pTWxaARdx\") + \"JkGNmbu\").sausage2();" fullword ascii
    $s10 = "function executive(garcia, disheartening) {" fullword ascii
    $s11 = "String.prototype.sausage = function () {" fullword ascii
    $s12 = "spread = \"b3Blbg==\".sausage4();;" fullword ascii
    $s13 = "String.prototype.sausage2 = function () {" fullword ascii
    $s14 = "String.prototype.sausage4 = function() {" fullword ascii
    $s15 = "        oppressor[\"d3JpdGU=\".sausage4()](predatory[(\"transcendent\",\"labyrinth\",\"encouraged\",\"dalliance\",\"paying\",\"t" ascii
    $s16 = "var punch =\"JVinternationalRFTVinternationalAl\".sausage4();" fullword ascii
    $s17 = "weasel = ((\"credits\", \"casual\", \"buried\", \"urine\", \"EkzXoWRsVU\") + \"GHJWXeU\").sausage2();" fullword ascii
    $s18 = "var librarian = \"QWinternationalN0aXZinternationallWE9iainternationalmVjdA=international=\".sausage4();" fullword ascii
    $s19 = "var wayside =\"RXhwYW5internationalkRW52aXinternationalJvbm1lbnRTdHJinternationalpbmdz\".sausage4();" fullword ascii
    $s20 = "        var oppressor = new humid(((\"lovely\",\"texts\",\"interim\",\"roland\",\"poseidon\",\"boxing\",\"vodka\",\"locale\",\"A" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}