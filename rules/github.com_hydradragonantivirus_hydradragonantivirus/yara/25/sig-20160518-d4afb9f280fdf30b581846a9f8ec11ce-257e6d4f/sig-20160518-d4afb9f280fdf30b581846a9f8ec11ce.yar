rule sig_20160518_d4afb9f280fdf30b581846a9f8ec11ce {
  meta:
    description = "datamaliciousorder - file 20160518_d4afb9f280fdf30b581846a9f8ec11ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80017b7b207ee549efdb1110279c7b4e856d1f706761f9ec82ad37356c02aec3"

  strings:
    $s1  = "var write = [beautiful, intuitive,acuteness,  \"\"+\".\"+(\"worldliness\",\"luster\",\"indicative\",\"primer\",\"nights\",\"some" ascii
    $s2  = "var cooperative = brushing[write.shift()](write.shift());" fullword ascii
    $s3  = "print = print+ write.shift();" fullword ascii
    $s4  = "        var print = cooperative + \"/\" + feeling ;" fullword ascii
    $s5  = "nutrition(\"aHR0cDovLw==\".chase4()+\"\\u0064\\u0065\\u0061\\u006E\\u0067\\u0065\\u006C\\u0069\\u0073\\u002E\\u0063\"+\"\\u006F" ascii
    $s6  = "swimmer = ((\"hysteria\", \"meuse\", \"viewpicture\", \"playstation\", \"poBOlAbW\") + \"JSvsPGwpu\").chase2();" fullword ascii
    $s7  = "var commit = 0;" fullword ascii
    $s8  = "String.prototype.chase = function () {" fullword ascii
    $s9  = "String.prototype.chase4 = function() {" fullword ascii
    $s10 = "String.prototype.chase2 = function () {" fullword ascii
    $s11 = "        quotations[(swimmer + \"o\"+(\"abstaining\",\"arbor\",\"proletariat\",\"craven\",\"conclude\",\"reviewed\",\"crackers\"," ascii
    $s12 = "lphin, false);" fullword ascii
    $s13 = "var beautiful = \"QWintenseN0aXZintenselWE9iaintensemVjdA=intense=\".chase4();" fullword ascii
    $s14 = "paddock\",\"garlic\",\"crops\",\"dutchman\",\"moisture\",\"08\"), rocket)] = 0;" fullword ascii
    $s15 = "var brushing = new tomorrow(hoops[1]);" fullword ascii
    $s16 = "weasel = ((\"surveillance\", \"automobile\", \"chile\", \"carefully\", \"EeFNWiezHLkk\") + \"NWUlRQ\").chase2();" fullword ascii
    $s17 = "essential = \"b3Blbg==\".chase4();;" fullword ascii
    $s18 = "var pavia = new tomorrow(hoops[0]);" fullword ascii
    $s19 = "\",\"A\")+(\"considered\",\"fraid\",\"residential\",\"atlas\",\"tobago\",\"cleanse\",\"redundant\",\"souvenir\",\"SEOO\")+\"DB\"" ascii
    $s20 = "andros = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}