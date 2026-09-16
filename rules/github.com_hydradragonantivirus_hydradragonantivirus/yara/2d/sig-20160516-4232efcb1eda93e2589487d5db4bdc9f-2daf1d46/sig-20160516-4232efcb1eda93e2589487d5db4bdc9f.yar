rule sig_20160516_4232efcb1eda93e2589487d5db4bdc9f {
  meta:
    description = "datamaliciousorder - file 20160516_4232efcb1eda93e2589487d5db4bdc9f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "870758eee77c9dacb83918c7df49c0dd9d8849945f50c444b3649d123b101135"

  strings:
    $s1  = "var ponder = [anteroom, angel,greenland,  \"\"+\".\"+(\"resources\",\"memory\",\"merit\",\"portmanteau\",\"childhood\",\"aucklan" ascii
    $s2  = "logged = \"_F2_\";" fullword ascii
    $s3  = "tacitly(\"aHR0cDovLw==\".treacle4()+\"\\u006E\\u006F\\u002D\\u0069\\u0064\\u002E\\u0065\\u0075\"+\"\\u002F\\u0039\\u0038\\u0037" ascii
    $s4  = "weasel = ((\"synthesis\", \"durham\", \"triangular\", \"remix\", \"EDyixkPm\") + \"KccefRb\").treacle2();" fullword ascii
    $s5  = "pregnant = pregnant+ ponder.shift();" fullword ascii
    $s6  = "var stroke = ponder.pop().split(\"" fullword ascii
    $s7  = "String.prototype.treacle = function () {" fullword ascii
    $s8  = "var ponder = [anteroom, angel,greenland,  \"\"+\".\"+(\"resources\",\"memory\",\"merit\",\"portmanteau\",\"childhood\",\"aucklan" ascii
    $s9  = "String.prototype.treacle4 = function() {" fullword ascii
    $s10 = "String.prototype.treacle2 = function () {" fullword ascii
    $s11 = "var cassandra=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".treacle4())&&locate[\"c3RhdHVz\".treacle4()] +\"\"==\"MjAw\".treac" ascii
    $s12 = "        hygiene[(accomplishing + \"o\"+(\"dimmer\",\"dishes\",\"scores\",\"openings\",\"mariah\",\"whitening\",\"gabriel\",\"pir" ascii
    $s13 = "var cassandra=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".treacle4())&&locate[\"c3RhdHVz\".treacle4()] +\"\"==\"MjAw\".treac" ascii
    $s14 = "quantity[ponder.shift()](pregnant, pillow, true);biIQuiL = \"_F17_\";" fullword ascii
    $s15 = "ty, false);" fullword ascii
    $s16 = "for (var i in trapper){apricot = apricot.replace(i, trapper[i]);}" fullword ascii
    $s17 = "var anteroom = \"QWN0aXZlWE9iamVjdA==\".treacle4();" fullword ascii
    $s18 = "apricot = this;" fullword ascii
    $s19 = "function tacitly(futility, charlatan) {" fullword ascii
    $s20 = "var quantity = new whove(stroke[1]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}