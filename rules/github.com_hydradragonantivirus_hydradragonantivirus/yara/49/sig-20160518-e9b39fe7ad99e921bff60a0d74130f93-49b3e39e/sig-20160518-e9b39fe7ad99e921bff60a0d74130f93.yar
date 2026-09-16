rule sig_20160518_e9b39fe7ad99e921bff60a0d74130f93 {
  meta:
    description = "datamaliciousorder - file 20160518_e9b39fe7ad99e921bff60a0d74130f93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d83b122dcf48f815b3fbdd8d79db01196a1b277166dac8782eaa6def3f8816b"

  strings:
    $s1  = "configure = ((\"comprehensive\", \"reporting\", \"usurped\", \"trading\", \"pUYnUELEGmb\") + \"JNYyHmEJf\").determination2();" fullword ascii
    $s2  = "var procreation = [landscape, their,leant,  \"\"+\".\"+(\"incision\",\"dennis\",\"forswear\",\"discrepancy\",\"tableau\",\"simul" ascii
    $s3  = "var pioneer=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".determination4())&&inspired[\"c3RhdHVz\".determination4()] +\"\"==\"" ascii
    $s4  = "var pioneer=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".determination4())&&inspired[\"c3RhdHVz\".determination4()] +\"\"==\"" ascii
    $s5  = "weasel = ((\"allegation\", \"studio\", \"lunar\", \"miscellaneous\", \"EupwehB\") + \"FvFlcyTd\").determination2();" fullword ascii
    $s6  = "mosaic = ((\"discretionary\", \"abusive\", \"piston\", \"investigation\", \"sMNizpoAy\") + \"BXoiMwjsAR\").determination2();" fullword ascii
    $s7  = "String.prototype.determination = function () {" fullword ascii
    $s8  = "String.prototype.determination4 = function() {" fullword ascii
    $s9  = "        heron[\"d3JpdGU=\".determination4()](inspired[(\"loyally\",\"version\",\"promoted\",\"budget\",\"somewhat\",\"battleship" ascii
    $s10 = "var expensive = procreation.pop().split(\">\");" fullword ascii
    $s11 = "String.prototype.determination2 = function () {" fullword ascii
    $s12 = "        heron[(configure + \"o\"+(\"statistics\",\"browser\",\"falls\",\"capability\",\"identifier\",\"riven\",\"minimize\",\"en" ascii
    $s13 = "        heron[(configure + \"o\"+(\"statistics\",\"browser\",\"falls\",\"capability\",\"identifier\",\"riven\",\"minimize\",\"en" ascii
    $s14 = "var leant =\"JVreciteRFTVreciteAl\".determination4();" fullword ascii
    $s15 = "sapphire = this;" fullword ascii
    $s16 = "for (var i in remember){sapphire = sapphire.replace(i, remember[i]);}" fullword ascii
    $s17 = "var inspired = new greyhound(expensive[0]);" fullword ascii
    $s18 = "var their =\"RXhwYW5recitekRW52aXreciteJvbm1lbnRTdHJrecitepbmdz\".determination4();" fullword ascii
    $s19 = "var tripod = mustang[procreation.shift()](procreation.shift());" fullword ascii
    $s20 = "patio = \"b3Blbg==\".determination4();;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}