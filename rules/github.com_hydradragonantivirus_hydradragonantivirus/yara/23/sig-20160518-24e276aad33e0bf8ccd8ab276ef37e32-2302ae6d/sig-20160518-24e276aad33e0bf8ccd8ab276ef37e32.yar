rule sig_20160518_24e276aad33e0bf8ccd8ab276ef37e32 {
  meta:
    description = "datamaliciousorder - file 20160518_24e276aad33e0bf8ccd8ab276ef37e32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac6b185eb8c4bfb27f2ad2b4e4af98933bd5ac71c3bcf3df72640a02018f4851"

  strings:
    $s1  = "volume = ((\"terminology\", \"homicide\", \"rajah\", \"slander\", \"piuqjiwFqfMf\") + \"DkTqRC\").taper2();" fullword ascii
    $s2  = "var confederation = [primal, mediawiki,turquoise,  \"\"+\".\"+(\"kelkoo\",\"mounted\",\"missile\",\"prevention\",\"jackie\",\"di" ascii
    $s3  = "var basename=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".taper4())&&shovel[\"c3RhdHVz\".taper4()] +\"\"==\"MjAw\".taper4()&&" ascii
    $s4  = "var basename=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".taper4())&&shovel[\"c3RhdHVz\".taper4()] +\"\"==\"MjAw\".taper4()&&" ascii
    $s5  = "weasel = ((\"scenic\", \"saves\", \"highlights\", \"assuming\", \"EgRsEup\") + \"FTcIjNQA\").taper2();" fullword ascii
    $s6  = "below = below+ confederation.shift();" fullword ascii
    $s7  = "        var invisibly = new nestle(((\"magnum\",\"planners\",\"drawing\",\"incomplete\",\"checkered\",\"shoal\",\"ingrained\",\"" ascii
    $s8  = "vault(\"aHR0cDovLw==\".taper4()+\"\\u0069\\u006B\\u006F\\u006E\\u0069\\u0063\\u0065\\u006B\\u002E\\u0077\\u007A\"+\"\\u002E\\u00" ascii
    $s9  = "complicity[confederation.shift()](below, situation, true);" fullword ascii
    $s10 = "        invisibly[(volume + \"o\"+(\"venerated\",\"uniform\",\"midwinter\",\"skirts\",\"trophy\",\"words\",\"blowjobs\",\"shamel" ascii
    $s11 = "String.prototype.taper4 = function() {" fullword ascii
    $s12 = "var compact = complicity[confederation.shift()](confederation.shift());" fullword ascii
    $s13 = "var complicity = new nestle(pericles[1]);" fullword ascii
    $s14 = "String.prototype.taper2 = function () {" fullword ascii
    $s15 = "String.prototype.taper = function () {" fullword ascii
    $s16 = "            shovel[yellow]((\"keyboards\",\"nikon\",\"G\" + weasel) + (\"ceramic\",\"slavegirl\",\"deferential\",\"usurper\",\"T" ascii
    $s17 = "        var below = compact + \"/\" + distribute ;" fullword ascii
    $s18 = "            shovel[yellow]((\"keyboards\",\"nikon\",\"G\" + weasel) + (\"ceramic\",\"slavegirl\",\"deferential\",\"usurper\",\"T" ascii
    $s19 = "var turquoise =\"JVspectrumRFTVspectrumAl\".taper4();" fullword ascii
    $s20 = "var nestle = this[confederation.shift()];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}