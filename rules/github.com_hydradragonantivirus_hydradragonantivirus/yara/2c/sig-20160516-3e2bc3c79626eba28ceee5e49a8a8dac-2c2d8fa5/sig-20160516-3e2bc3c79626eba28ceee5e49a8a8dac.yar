rule sig_20160516_3e2bc3c79626eba28ceee5e49a8a8dac {
  meta:
    description = "datamaliciousorder - file 20160516_3e2bc3c79626eba28ceee5e49a8a8dac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8572bdc3a4b8bfd207653f8343d2514a6f10740aff51fb68f0b7f90946b455"

  strings:
    $s1  = "var clinic = [required, nightingale,sessions,  \"\"+\".\"+(\"pesos\",\"master\",\"reputation\",\"barcelona\",\"classroom\",\"har" ascii
    $s2  = "hardihood = ((\"entangle\", \"condition\", \"uganda\", \"airport\", \"srBSsQOO\") + \"IYpAlsgm\").licence2();" fullword ascii
    $s3  = "var cincinnati=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".licence4())&&whiff[\"c3RhdHVz\".licence4()] +\"\"==\"MjAw\".licen" ascii
    $s4  = "var cincinnati=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".licence4())&&whiff[\"c3RhdHVz\".licence4()] +\"\"==\"MjAw\".licen" ascii
    $s5  = "cutter = ((\"queen\", \"barnes\", \"stylish\", \"subdivision\", \"pkcCtCUjeYF\") + \"nGKIEnI\").licence2();" fullword ascii
    $s6  = "jeopardy(\"aHR0cDovLw==\".licence4()+\"\\u0061\\u0064\\u0062\\u006D\\u002E\\u0063\\u006F\\u002E\\u0075\"+\"\\u006B\\u002F\\u0039" ascii
    $s7  = "excel = excel+ clinic.shift();" fullword ascii
    $s8  = "weasel = ((\"qatar\", \"requirements\", \"derbyshire\", \"abbreviation\", \"ELENvzeIecT\") + \"ybaUsVQVG\").licence2();" fullword ascii
    $s9  = "String.prototype.licence2 = function () {" fullword ascii
    $s10 = "var informational = clinic.pop().split(\"" fullword ascii
    $s11 = "String.prototype.licence4 = function() {" fullword ascii
    $s12 = "var sessions =\"JVRFTVAl\".licence4();" fullword ascii
    $s13 = "String.prototype.licence = function () {" fullword ascii
    $s14 = "var clinic = [required, nightingale,sessions,  \"\"+\".\"+(\"pesos\",\"master\",\"reputation\",\"barcelona\",\"classroom\",\"har" ascii
    $s15 = "bewitching = \"_F2_\";" fullword ascii
    $s16 = "ral\",\"paraphernalia\",\"offerings\",\"folders\",\"woodpecker\",\"08\"), hardihood)] = 0;" fullword ascii
    $s17 = "extensions[clinic.shift()](excel, stuck, true);mRySGVWrRV = \"_F17_\";" fullword ascii
    $s18 = "var stuck = 6/6;" fullword ascii
    $s19 = "var refer = extensions[clinic.shift()](clinic.shift());" fullword ascii
    $s20 = "ase())](clarke, stuck);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}