rule sig_20160518_854cfc63c6bc703f36baf95abd700fad {
  meta:
    description = "datamaliciousorder - file 20160518_854cfc63c6bc703f36baf95abd700fad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40b777ce3700ca4db6069b29e045c337f15cd4b4ac0520489306b6f34fe737c2"

  strings:
    $s1  = "var ordering = [condense, modifies,barnet,  \"\"+\".\"+(\"titans\",\"floyd\",\"bristling\",\"profuse\",\"powerful\",\"treasury\"" ascii
    $s2  = "        var matthew = new creditor(((\"slash\",\"dumfounded\",\"quicken\",\"print\",\"peninsula\",\"leave\",\"gallic\",\"theta\"" ascii
    $s3  = "var deposit=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".merge4())&&housing[\"c3RhdHVz\".merge4()] +\"\"==\"MjAw\".merge4()&&" ascii
    $s4  = "var deposit=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".merge4())&&housing[\"c3RhdHVz\".merge4()] +\"\"==\"MjAw\".merge4()&&" ascii
    $s5  = "var ordering = [condense, modifies,barnet,  \"\"+\".\"+(\"titans\",\"floyd\",\"bristling\",\"profuse\",\"powerful\",\"treasury\"" ascii
    $s6  = "weasel = ((\"manitoba\", \"platforms\", \"reviewing\", \"adjacent\", \"EyWKurnGfx\") + \"JYXSrwdtV\").merge2();" fullword ascii
    $s7  = "acidity(\"aHR0cDovLw==\".merge4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067\\u" ascii
    $s8  = "ker\",\"pepper\",\"clipping\",\"submission\",\"cited\",\"disability\",\"P>\")+\"WU\"+(\"circus\",\"terrible\",\"listening\",\"qu" ascii
    $s9  = "var minutiae = ordering.pop().split(\">\");" fullword ascii
    $s10 = "String.prototype.merge = function () {" fullword ascii
    $s11 = "String.prototype.merge4 = function() {" fullword ascii
    $s12 = "String.prototype.merge2 = function () {" fullword ascii
    $s13 = "var finish = 0;" fullword ascii
    $s14 = "var creditor = this[ordering.shift()];" fullword ascii
    $s15 = "var emigration = 6/6;" fullword ascii
    $s16 = "acidity(\"aHR0cDovLw==\".merge4()+\"\\u006F\\u0061\\u0076\\u0062\\u002E\\u0063\\u006F\\u006D\"+\"\\u002F\\u0065\\u0072\\u0067\\u" ascii
    $s17 = "var housing = new creditor(minutiae[0]);" fullword ascii
    $s18 = "  anonymous = [];" fullword ascii
    $s19 = "sarah = this;" fullword ascii
    $s20 = "function acidity(valencia, reproduce) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}