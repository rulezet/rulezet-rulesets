rule sig_20160519_5dedef54e0fb8dd7dd1bde168fbff306 {
  meta:
    description = "datamaliciousorder - file 20160519_5dedef54e0fb8dd7dd1bde168fbff306.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fd58da181d98f1396003754d52287e3c0f4637264aefde4b4f1937310eb1ff8"

  strings:
    $s1  = "var befit = [neutralize, bruising,cleveland,  \"\"+\".\"+(\"queensland\",\"strut\",\"havoc\",\"assumed\",\"undisputed\",\"signif" ascii
    $s2  = "var advertising=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tunes4())&&driver[\"c3RhdHVz\".tunes4()] +\"\"==\"MjAw\".tunes4(" ascii
    $s3  = "var advertising=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".tunes4())&&driver[\"c3RhdHVz\".tunes4()] +\"\"==\"MjAw\".tunes4(" ascii
    $s4  = "crusty = ((\"invoice\", \"creation\", \"committee\", \"predilection\", \"pvkbWpSQ\") + \"cdLAUK\").tunes2();" fullword ascii
    $s5  = "    driver[downloading + (\"cottages\",\"publications\",\"end\")]();" fullword ascii
    $s6  = "        ballot[(crusty + \"o\"+(\"accessories\",\"overhead\",\"dissimilar\",\"traveler\",\"martial\",\"educated\",\"herald\",\"c" ascii
    $s7  = "weasel = ((\"northumberland\", \"projection\", \"lutheran\", \"expect\", \"ELTjyydAcL\") + \"rtvobwDKe\").tunes2();" fullword ascii
    $s8  = "insidious(\"aHR0cDovLw==\".tunes4()+\"\\u0070\\u0069\\u0070\\u0074\\u002E\\u0077\\u0061\\u006C\\u006C\\u0073\\u0074\\u002E\"+\"" ascii
    $s9  = "var warrior = befit.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.tunes = function () {" fullword ascii
    $s11 = "String.prototype.tunes4 = function() {" fullword ascii
    $s12 = "        ballot[\"d3JpdGU=\".tunes4()](driver[(\"dialectic\",\"russian\",\"burmese\",\"separate\",\"jointed\",\"geology\",\"smugg" ascii
    $s13 = "String.prototype.tunes2 = function () {" fullword ascii
    $s14 = "var driver = new bairn(warrior[0]);" fullword ascii
    $s15 = "            driver[derived]((\"office\",\"chequered\",\"G\" + weasel) + (\"years\",\"thumbs\",\"fiftyeight\",\"dunno\",\"T\"), z" ascii
    $s16 = "        ballot[(\"griffin\",\"bologna\",\"hazard\",\"stainless\",\"moderately\",\"meetings\",\"relax\",\"s\")+\"aveT\"+\"oF\"+\"" ascii
    $s17 = "var bruising =\"RXhwYW5zoneskRW52aXzonesJvbm1lbnRTdHJzonespbmdz\".tunes4();" fullword ascii
    $s18 = "sense = this;" fullword ascii
    $s19 = "function insidious(zones, inferno) {" fullword ascii
    $s20 = "derived = \"b3Blbg==\".tunes4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}