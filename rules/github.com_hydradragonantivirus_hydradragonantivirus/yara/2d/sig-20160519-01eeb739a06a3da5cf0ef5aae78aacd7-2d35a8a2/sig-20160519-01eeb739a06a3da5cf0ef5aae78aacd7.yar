rule sig_20160519_01eeb739a06a3da5cf0ef5aae78aacd7 {
  meta:
    description = "datamaliciousorder - file 20160519_01eeb739a06a3da5cf0ef5aae78aacd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "605acaa20e35f1a3907279d6fbdc3cc19841c34708ca4a5af1d28c599d753fb8"

  strings:
    $s1  = "var congratulation = [beacon, evasive,initial,  \"\"+\".\"+(\"temperature\",\"penalty\",\"remedial\",\"heterogeneous\",\"bedlam" ascii
    $s2  = "var congratulation = [beacon, evasive,initial,  \"\"+\".\"+(\"temperature\",\"penalty\",\"remedial\",\"heterogeneous\",\"bedlam" ascii
    $s3  = "weasel = ((\"failed\", \"potential\", \"slush\", \"segment\", \"EFoobuEUv\") + \"fwCHvzNVPG\").daddy2();" fullword ascii
    $s4  = "var suzerain=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".daddy4())&&differ[\"c3RhdHVz\".daddy4()] +\"\"==\"MjAw\".daddy4()&&" ascii
    $s5  = "var suzerain=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".daddy4())&&differ[\"c3RhdHVz\".daddy4()] +\"\"==\"MjAw\".daddy4()&&" ascii
    $s6  = "benediction = ((\"paucity\", \"swims\", \"spans\", \"babylonian\", \"assignment\", \"monroe\", \"spubJVC\") + \"ldKTIF\").daddy2" ascii
    $s7  = "forceful = forceful+ congratulation.shift();" fullword ascii
    $s8  = "pledge(\"aHR0cDovLw==\".daddy4()+\"\\u006E\\u0065\\u0077\\u0072\\u006F\\u006D\\u006E\\u0065\\u0079\\u006F\\u006C\\u0064\\u0073" ascii
    $s9  = "crackling = ((\"guaranteed\", \"victual\", \"gravy\", \"condition\", \"pynDYHaYA\") + \"vRVFSxQxe\").daddy2();" fullword ascii
    $s10 = "        var coalition = new wizard(((\"brain\",\"turns\",\"obtainable\",\"accomplishes\",\"together\",\"luxembourg\",\"noose\"," ascii
    $s11 = "String.prototype.daddy = function () {" fullword ascii
    $s12 = "        var coalition = new wizard(((\"brain\",\"turns\",\"obtainable\",\"accomplishes\",\"together\",\"luxembourg\",\"noose\"," ascii
    $s13 = "String.prototype.daddy4 = function() {" fullword ascii
    $s14 = "var commonwealth = 0;" fullword ascii
    $s15 = "String.prototype.daddy2 = function () {" fullword ascii
    $s16 = "quill = this;" fullword ascii
    $s17 = "function pledge(thong, coincident) {" fullword ascii
    $s18 = "var wizard = this[congratulation.shift()];" fullword ascii
    $s19 = "pledge(\"aHR0cDovLw==\".daddy4()+\"\\u006E\\u0065\\u0077\\u0072\\u006F\\u006D\\u006E\\u0065\\u0079\\u006F\\u006C\\u0064\\u0073" ascii
    $s20 = "  roger = [];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}