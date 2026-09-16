rule sig_20160517_b7dc686a6f51c742ab1e17461307e37b {
  meta:
    description = "datamaliciousorder - file 20160517_b7dc686a6f51c742ab1e17461307e37b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3945fe5a9f2baf69f5d220f74051a3bf1b5a2176f2a87c701c91149414110bd"

  strings:
    $s1  = "bestowal = bestowal+ incompleteness.shift();" fullword ascii
    $s2  = "var pediatric = incompleteness.pop().split(\"" fullword ascii
    $s3  = "var forte = \"QWN0geologistaXZlWE9igeologistamVjdA==geologist\".separated4();" fullword ascii
    $s4  = "scorching = ((\"quietude\", \"wherever\", \"bereft\", \"peeing\", \"pWWhNevlqFI\") + \"WBIyOwNYO\").separated2();" fullword ascii
    $s5  = "fader(\"aHR0cDovLw==\".separated4()+\"\\u006E\\u0061\\u0074\\u0061\\u006C\\u0069\\u0065\\u0064\\u0075\\u0064\\u0061\\u0073\\u007" ascii
    $s6  = "weasel = ((\"saber\", \"lusty\", \"uprightness\", \"house\", \"EyaKazvToQU\") + \"XxlYOHl\").separated2();" fullword ascii
    $s7  = "var incompleteness = [forte, intrepid,scabbard,  \"\"+\".\"+(\"joker\",\"brescia\",\"stupidly\",\"nuclear\",\"undoing\",\"merito" ascii
    $s8  = "var pontiff = cosmetic[incompleteness.shift()](incompleteness.shift());" fullword ascii
    $s9  = "String.prototype.separated = function () {" fullword ascii
    $s10 = "var dominoes = this[incompleteness.shift()];" fullword ascii
    $s11 = "String.prototype.separated2 = function () {" fullword ascii
    $s12 = "String.prototype.separated4 = function() {" fullword ascii
    $s13 = "cosmetic[incompleteness.shift()](bestowal, agricultural, true);" fullword ascii
    $s14 = "var baptize = {" fullword ascii
    $s15 = "        quicksand[(scorching + \"o\"+(\"blackguard\",\"replication\",\"flaunt\",\"disconsolate\",\"cleaners\",\"courage\",\"inco" ascii
    $s16 = "crystalline = this;" fullword ascii
    $s17 = "var agricultural = 6/6;" fullword ascii
    $s18 = "for (var i in baptize){crystalline = crystalline.replace(i, baptize[i]);}" fullword ascii
    $s19 = "var intrepid =\"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdz\".separated4();" fullword ascii
    $s20 = "var draws = new dominoes(pediatric[0]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}