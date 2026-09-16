rule sig_20160518_c46a6ba14f95f3b6c36d9ed5a923d227 {
  meta:
    description = "datamaliciousorder - file 20160518_c46a6ba14f95f3b6c36d9ed5a923d227.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df2e0912cb31e5106fb856e8306a83e5e529a1b9adbe374421cbb9293870f63"

  strings:
    $s1  = "piston = ((\"compensating\", \"hostels\", \"integration\", \"trout\", \"siCNTzyl\") + \"nGBKYNP\").planetary2();" fullword ascii
    $s2  = "var cultures = [imprint, hooked,abounded,  \"\"+\".\"+(\"mixing\",\"truthfulness\",\"theoretical\",\"remedy\",\"coordinates\",\"" ascii
    $s3  = "    refer.citations = refer.scripting[\"c3Vic3RyaW5n\".planetary4()](grieving, authorize);" fullword ascii
    $s4  = "var browser=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".planetary4())&&imperceptible[\"c3RhdHVz\".planetary4()] +\"\"==\"MjA" ascii
    $s5  = "var browser=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".planetary4())&&imperceptible[\"c3RhdHVz\".planetary4()] +\"\"==\"MjA" ascii
    $s6  = "visiting[cultures.shift()](environments, authorize, true);" fullword ascii
    $s7  = "whooping = \"b3Blbg==\".planetary4();;" fullword ascii
    $s8  = "String.prototype.planetary4 = function() {" fullword ascii
    $s9  = "var simulation = cultures.pop().split(\">\");" fullword ascii
    $s10 = "var authorize = 6/6;" fullword ascii
    $s11 = "String.prototype.planetary2 = function () {" fullword ascii
    $s12 = "String.prototype.planetary = function () {" fullword ascii
    $s13 = "        var environments = delectation + \"/\" + swooping ;" fullword ascii
    $s14 = "        scripting: this" fullword ascii
    $s15 = "weasel = ((\"shrub\", \"desktop\", \"caribbean\", \"blasted\", \"EeXrfUdaao\") + \"RKdNrsLaTEM\").planetary2();" fullword ascii
    $s16 = "var hooked =\"RXhwYW5affiliatedkRW52aXaffiliatedJvbm1lbnRTdHJaffiliatedpbmdz\".planetary4();" fullword ascii
    $s17 = "var grieving = 0;" fullword ascii
    $s18 = "var promise = {" fullword ascii
    $s19 = "for (var i in promise){blacks = blacks.replace(i, promise[i]);}" fullword ascii
    $s20 = "var delectation = visiting[cultures.shift()](cultures.shift());" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}