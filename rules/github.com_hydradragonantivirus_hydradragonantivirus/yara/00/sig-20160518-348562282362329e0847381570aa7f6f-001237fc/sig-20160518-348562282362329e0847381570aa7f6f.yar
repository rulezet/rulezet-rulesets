rule sig_20160518_348562282362329e0847381570aa7f6f {
  meta:
    description = "datamaliciousorder - file 20160518_348562282362329e0847381570aa7f6f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7910dc56db2d281ce29d67a9737f76cb75eda9cf26decfe25285438752402f9f"

  strings:
    $s1  = "var amanda = [demure, invert,living,  \"\"+\".\"+(\"flash\",\"seconds\",\"congratulation\",\"greyhound\",\"schism\",\"flagstaff" ascii
    $s2  = "circumspect = ((\"query\", \"verbs\", \"syndicate\", \"artifice\", \"pVHFihb\") + \"azlILw\").underfoot2();" fullword ascii
    $s3  = "        sheep[(circumspect + \"o\"+(\"humid\",\"abstained\",\"drawings\",\"cupidity\",\"gallon\",\"coordinates\",\"scientist\"," ascii
    $s4  = "        sheep[(circumspect + \"o\"+(\"humid\",\"abstained\",\"drawings\",\"cupidity\",\"gallon\",\"coordinates\",\"scientist\"," ascii
    $s5  = "enhance(\"aHR0cDovLw==\".underfoot4()+\"\\u006D\\u0061\\u0072\\u0063\\u0068\\u0061\\u006E\\u0064\\u0065\\u0064\\u0069\\u0064\\u0" ascii
    $s6  = "weasel = ((\"iniquitous\", \"mediocrity\", \"raymond\", \"triumph\", \"EGUtMTsCBx\") + \"rkSDcW\").underfoot2();" fullword ascii
    $s7  = "String.prototype.underfoot4 = function() {" fullword ascii
    $s8  = "String.prototype.underfoot = function () {" fullword ascii
    $s9  = "String.prototype.underfoot2 = function () {" fullword ascii
    $s10 = ",\"completion\",\"observed\",\"leinster\",\"teens\",\"seeing\",\"P>\")+\"WU\"+(\"assurance\",\"association\",\"indians\",\"local" ascii
    $s11 = "        var sheep = new demolish(((\"inkjet\",\"wheat\",\"notoriously\",\"gregarious\",\"purse\",\"dozen\",\"immediate\",\"paren" ascii
    $s12 = "var demure = \"QWcrapsN0aXZcrapslWE9iacrapsmVjdA=craps=\".underfoot4();" fullword ascii
    $s13 = "var amanda = [demure, invert,living,  \"\"+\".\"+(\"flash\",\"seconds\",\"congratulation\",\"greyhound\",\"schism\",\"flagstaff" ascii
    $s14 = "forum = \"_F2_\";" fullword ascii
    $s15 = "var demented = 0;" fullword ascii
    $s16 = "function enhance(mangy, groundwater) {" fullword ascii
    $s17 = "var sandal = {" fullword ascii
    $s18 = "beryl = \"b3Blbg==\".underfoot4();;" fullword ascii
    $s19 = "ongoing = this;" fullword ascii
    $s20 = "var demolish = this[amanda.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}