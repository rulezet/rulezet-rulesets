rule sig_20160517_12751a7db7cf7ad2734424c87b7a1e03 {
  meta:
    description = "datamaliciousorder - file 20160517_12751a7db7cf7ad2734424c87b7a1e03.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f944fe136e263a09b32de6dcb43069c8fb35b44a43a6dcdc0130a307dc4be97"

  strings:
    $s1  = "var label = [offal, journalist,nascent,  \"\"+\".\"+(\"boomed\",\"construction\",\"indianapolis\",\"assistance\",\"civil\",\"tac" ascii
    $s2  = "\"assault\",\"green\",\"knack\",\"flood\",\"eightythree\",\"grandparents\",\"paragon\",\"2.\")+\"XM\"+\"LH\"+\"TT\"+(\"recruit\"" ascii
    $s3  = "    abolishing.drawback = abolishing.sperm[((\"adobe\",\"bewail\",\"blogging\",\"micah\",\"comparing\",\"advertise\",\"physiogno" ascii
    $s4  = "polar = ((\"wages\", \"poniard\", \"honey\", \"initiated\", \"peYOxMwnnSW\") + \"AesYJfNygwy\").selene2();" fullword ascii
    $s5  = "underhand(\"aHR0cDovLw==\".selene4()+\"\\u006D\\u0075\\u0072\\u0069\\u006E\\u002E\\u006E\\u0065\"+\"\\u0074\\u002F\\u0030\\u0075" ascii
    $s6  = "String.prototype.selene2 = function () {" fullword ascii
    $s7  = "String.prototype.selene = function () {" fullword ascii
    $s8  = "String.prototype.selene4 = function() {" fullword ascii
    $s9  = "var showcase=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".selene4())&&sheriff[\"c3RhdHVz\".selene4()] +\"\"==\"MjAw\".selene4" ascii
    $s10 = ",\"s\")+\"ubRt\"+(\"scripts\",\"parsley\",\"middleclass\",\"cisco\",\"samsung\",\"clothes\",\"sward\",\"ri\")+\"ng\").replace(\"" ascii
    $s11 = "var showcase=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".selene4())&&sheriff[\"c3RhdHVz\".selene4()] +\"\"==\"MjAw\".selene4" ascii
    $s12 = "weasel = ((\"manager\", \"educate\", \"simplified\", \"geometry\", \"EfHYrxdawlMw\") + \"uovRKHpCMX\").selene2();" fullword ascii
    $s13 = "  colonist = [];" fullword ascii
    $s14 = "var reviewer = pegasus[label.shift()](label.shift());" fullword ascii
    $s15 = "var label = [offal, journalist,nascent,  \"\"+\".\"+(\"boomed\",\"construction\",\"indianapolis\",\"assistance\",\"civil\",\"tac" ascii
    $s16 = "pegasus[label.shift()](stronger, beleaguered, true);NdCXebQE = \"_F17_\";" fullword ascii
    $s17 = "        var boxed = new shameless(((\"abdul\",\"fraught\",\"patio\",\"mining\",\"coincide\",\"tablets\",\"taken\",\"ambrosia\"," ascii
    $s18 = "var palliate = 0;" fullword ascii
    $s19 = "underhand(\"aHR0cDovLw==\".selene4()+\"\\u006D\\u0075\\u0072\\u0069\\u006E\\u002E\\u006E\\u0065\"+\"\\u0074\\u002F\\u0030\\u0075" ascii
    $s20 = "var nascent =\"JVscratchRFTVscratchAl\".selene4();" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}