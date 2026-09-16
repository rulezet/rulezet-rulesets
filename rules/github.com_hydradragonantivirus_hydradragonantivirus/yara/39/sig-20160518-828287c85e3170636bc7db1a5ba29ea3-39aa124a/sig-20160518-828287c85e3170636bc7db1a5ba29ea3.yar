rule sig_20160518_828287c85e3170636bc7db1a5ba29ea3 {
  meta:
    description = "datamaliciousorder - file 20160518_828287c85e3170636bc7db1a5ba29ea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f6e489ad5befee02f15397a6d287e9b855c5db1112e4bf6c0764c9d0afd28d"

  strings:
    $s1  = "weasel = ((\"systems\", \"spending\", \"investigators\", \"unsightly\", \"ElywUJkk\") + \"spmAgsdVf\").sudden2();" fullword ascii
    $s2  = "var skeptical = [seattle, bulgarian,impressive,  \"\"+\".\"+(\"television\",\"fudge\",\"plaudits\",\"enabling\",\"deemed\",\"bar" ascii
    $s3  = "            selfevident[mumbai]((\"youthfulness\",\"applied\",\"G\" + weasel) + (\"decreased\",\"glaze\",\"postpone\",\"graham\"" ascii
    $s4  = "            selfevident[mumbai]((\"youthfulness\",\"applied\",\"G\" + weasel) + (\"decreased\",\"glaze\",\"postpone\",\"graham\"" ascii
    $s5  = "        var treasures = hymen + \"/\" + headed ;" fullword ascii
    $s6  = "String.prototype.sudden = function () {" fullword ascii
    $s7  = "String.prototype.sudden2 = function () {" fullword ascii
    $s8  = "String.prototype.sudden4 = function() {" fullword ascii
    $s9  = "function chemical(befriend, headed) {" fullword ascii
    $s10 = "d, false);" fullword ascii
    $s11 = "  review = [];" fullword ascii
    $s12 = "var pronunciation = 0;" fullword ascii
    $s13 = "quantum = this;" fullword ascii
    $s14 = "chemical(\"aHR0cDovLw==\".sudden4()+\"\\u0066\\u0065\\u0065\\u0064\\u0063\\u006F\\u006E\\u0073\\u0075\\u006D\\u0065\\u0072\\u002" ascii
    $s15 = "for (var i in vbulletin){quantum = quantum.replace(i, vbulletin[i]);}" fullword ascii
    $s16 = "var chafe = 6/6;" fullword ascii
    $s17 = "var impressive =\"JVunmannedRFTVunmannedAl\".sudden4();" fullword ascii
    $s18 = "signet = \"_F2_\";" fullword ascii
    $s19 = "var selfevident = new widescreen(flexible[0]);" fullword ascii
    $s20 = "\"+\"ML\"+(\"tower\",\"scholastic\",\"veterans\",\"unlettered\",\"deride\",\"articulate\",\"impecunious\",\"2.\")+\"|M\"+\"LH\"+" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}