rule sig_20160516_005c6906980e5f5f4f11dd0357b73e32 {
  meta:
    description = "datamaliciousorder - file 20160516_005c6906980e5f5f4f11dd0357b73e32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb659b2eaf1595f121d364359de37a1862cbd6216572029c30d6bc8cb970ac12"

  strings:
    $s1  = "var lackey = [stinging, engaged,unrest,  \"\"+\".\"+(\"phantasy\",\"bloodthirsty\",\"oasis\",\"melodrama\",\"indomitable\",\"ser" ascii
    $s2  = "reticent = reticent+ lackey.shift();" fullword ascii
    $s3  = "\"s\")+\"ubRt\"+(\"carving\",\"bless\",\"highly\",\"sprite\",\"traverse\",\"thompson\",\"scientist\",\"ri\")+\"ng\").replace(\"R" ascii
    $s4  = "grown = ((\"tariff\", \"commonwealth\", \"knuckle\", \"ferrari\", \"smUyESxw\") + \"vLhSQlawKt\").pessimistic2();" fullword ascii
    $s5  = "for (var i in passport){burner = burner.replace(i, passport[i]);}" fullword ascii
    $s6  = "var passport = {" fullword ascii
    $s7  = "promenade(\"aHR0cDovLw==\".pessimistic4()+\"\\u0077\\u0077\\u0077\\u002E\\u0070\\u0075\\u0065\\u0072\\u0074\\u0061\\u0073\\u006A" ascii
    $s8  = "    peeps[grown + (\"circular\",\"conversely\",\"end\")]();" fullword ascii
    $s9  = "weasel = ((\"transform\", \"conjuring\", \"terminating\", \"quotes\", \"EyaLbIhzE\") + \"QXTSCYTQAVC\").pessimistic2();" fullword ascii
    $s10 = "var lackey = [stinging, engaged,unrest,  \"\"+\".\"+(\"phantasy\",\"bloodthirsty\",\"oasis\",\"melodrama\",\"indomitable\",\"ser" ascii
    $s11 = "syracuse[lackey.shift()](reticent, students, true);ChICNdx = \"_F17_\";" fullword ascii
    $s12 = "String.prototype.pessimistic4 = function() {" fullword ascii
    $s13 = "var bulge = this[lackey.shift()];" fullword ascii
    $s14 = "String.prototype.pessimistic2 = function () {" fullword ascii
    $s15 = "var infringe = syracuse[lackey.shift()](lackey.shift());" fullword ascii
    $s16 = "String.prototype.pessimistic = function () {" fullword ascii
    $s17 = "        rehearsal[(\"coordination\",\"avowal\",\"thong\",\"tormentor\",\"informant\",\"emolument\",\"sleep\",\"w\")+\"ri\"+\"te" ascii
    $s18 = "var cataclysm = lackey.pop().split(\"" fullword ascii
    $s19 = "    coaches.swedish = coaches.arson[((\"kidney\",\"genre\",\"nicholas\",\"laboriously\",\"parsimonious\",\"sensitive\",\"researc" ascii
    $s20 = "amanuensis = \"b3Blbg==\".pessimistic4();;" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}