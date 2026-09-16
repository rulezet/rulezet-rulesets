rule sig_20160519_901452dc674f8f034e5ef9d93ec8a4cb {
  meta:
    description = "datamaliciousorder - file 20160519_901452dc674f8f034e5ef9d93ec8a4cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15782943108418e972082cb721f2e86921c2cc4630485087151b198191854b10"

  strings:
    $s1  = "var impervious = [beaker, shortening,isaac,  \"\"+\".\"+(\"libels\",\"witticism\",\"inflame\",\"tradesmen\",\"kernel\",\"disaffe" ascii
    $s2  = "        mauritania[(closer + \"o\"+(\"abrogated\",\"functionality\",\"clone\",\"query\",\"entries\",\"strictly\",\"lancashire\"," ascii
    $s3  = "und\",\"cr\")+(\"excavation\",\"monumental\",\"corvette\",\"temporal\",\"icing\",\"motif\",\"inimitable\",\"surface\",\"ip\")+\"" ascii
    $s4  = "var jaundice=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sponsorship4())&&patrician[\"c3RhdHVz\".sponsorship4()] +\"\"==\"Mj" ascii
    $s5  = "var jaundice=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sponsorship4())&&patrician[\"c3RhdHVz\".sponsorship4()] +\"\"==\"Mj" ascii
    $s6  = "var impervious = [beaker, shortening,isaac,  \"\"+\".\"+(\"libels\",\"witticism\",\"inflame\",\"tradesmen\",\"kernel\",\"disaffe" ascii
    $s7  = "fraction = fraction+ impervious.shift();" fullword ascii
    $s8  = "String.prototype.sponsorship2 = function () {" fullword ascii
    $s9  = "String.prototype.sponsorship4 = function() {" fullword ascii
    $s10 = "var apartment = impervious.pop().split(\">\");" fullword ascii
    $s11 = "String.prototype.sponsorship = function () {" fullword ascii
    $s12 = "var upheaval = 6/6;" fullword ascii
    $s13 = "var patrician = new macromedia(apartment[0]);" fullword ascii
    $s14 = "folding = this;" fullword ascii
    $s15 = "  roseate = [];" fullword ascii
    $s16 = "weasel = ((\"lengthen\", \"questioner\", \"twill\", \"castilian\", \"EMcDOnd\") + \"fUmBMjiF\").sponsorship2();" fullword ascii
    $s17 = "var beetles = spasm[impervious.shift()](impervious.shift());" fullword ascii
    $s18 = "function dorset(cumulative, purge) {" fullword ascii
    $s19 = "var spasm = new macromedia(apartment[1]);" fullword ascii
    $s20 = "asthma = \"b3Blbg==\".sponsorship4();;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}