rule sig_20160518_aef7fc48c5d569160b0ff58a319544cd {
  meta:
    description = "datamaliciousorder - file 20160518_aef7fc48c5d569160b0ff58a319544cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7f2e05cf6d26d8d45850792c435a1c6ccce2d0761a492d3c7b6ac98406b70a4"

  strings:
    $s1  = "var dogged = [irate, nipple,artwork,  \"\"+\".\"+(\"starred\",\"signup\",\"solvent\",\"firms\",\"characterized\",\"wayfarer\",\"" ascii
    $s2  = "var usenet=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".courage4())&&acquisition[\"c3RhdHVz\".courage4()] +\"\"==\"MjAw\".cou" ascii
    $s3  = "var usenet=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".courage4())&&acquisition[\"c3RhdHVz\".courage4()] +\"\"==\"MjAw\".cou" ascii
    $s4  = "weasel = ((\"dickie\", \"demeanor\", \"acute\", \"malevolent\", \"EXGRNsp\") + \"TvKdPhOSN\").courage2();" fullword ascii
    $s5  = "marksman(\"aHR0cDovLw==\".courage4()+\"\\u006E\\u006F\\u006C\\u0077\\u006F\\u006F\\u0064\\u006C\\u0061\\u006E\\u0064\"+\"\\u002E" ascii
    $s6  = "fullness = ((\"astounding\", \"receiving\", \"benighted\", \"sherman\", \"pidUHLbjhm\") + \"RtHJvVSlFaW\").courage2();" fullword ascii
    $s7  = "String.prototype.courage = function () {" fullword ascii
    $s8  = "String.prototype.courage4 = function() {" fullword ascii
    $s9  = "String.prototype.courage2 = function () {" fullword ascii
    $s10 = "var direct = dogged.pop().split(\">\");" fullword ascii
    $s11 = "var antediluvian = 0;" fullword ascii
    $s12 = "var nipple =\"RXhwYW5covetouskRW52aXcovetousJvbm1lbnRTdHJcovetouspbmdz\".courage4();" fullword ascii
    $s13 = "entrust = \"_F2_\";" fullword ascii
    $s14 = "            acquisition[trigger]((\"steppe\",\"seville\",\"G\" + weasel) + (\"mammy\",\"nikon\",\"unsympathetic\",\"diffs\",\"T" ascii
    $s15 = "var dogged = [irate, nipple,artwork,  \"\"+\".\"+(\"starred\",\"signup\",\"solvent\",\"firms\",\"characterized\",\"wayfarer\",\"" ascii
    $s16 = "var inarticulate = pragmatic[dogged.shift()](dogged.shift());" fullword ascii
    $s17 = "  decrease = [];" fullword ascii
    $s18 = "pragmatic[dogged.shift()](bedford, tinsel, true);" fullword ascii
    $s19 = "var pragmatic = new obituary(direct[1]);" fullword ascii
    $s20 = "var revere = {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}