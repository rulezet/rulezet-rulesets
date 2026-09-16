rule sig_20160518_edc9c1cdf8d56084c7df8a94ae0585f3 {
  meta:
    description = "datamaliciousorder - file 20160518_edc9c1cdf8d56084c7df8a94ae0585f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59f39aa0cfe40a34a9b3c7e3ce317b1255474d0bf5a06792e57bbaeeffc3aa03"

  strings:
    $s1  = "var innovation = [warble, transform,harried,  \"\"+\".\"+(\"restriction\",\"lighthouse\",\"nickel\",\"sultry\",\"circumstances\"" ascii
    $s2  = "var innovation = [warble, transform,harried,  \"\"+\".\"+(\"restriction\",\"lighthouse\",\"nickel\",\"sultry\",\"circumstances\"" ascii
    $s3  = "function meyer(squaw, turtle) {" fullword ascii
    $s4  = "manipulate = ((\"gongs\", \"euripides\", \"granary\", \"cripple\", \"pLOoUEiPlnif\") + \"DBPciGGbEGR\").knack2();" fullword ascii
    $s5  = "weasel = ((\"bangladesh\", \"plumber\", \"sensitivity\", \"tanker\", \"ENKFYJAtWxJy\") + \"nDpgaOmwtVd\").knack2();" fullword ascii
    $s6  = "martial = ((\"begone\", \"sepulture\", \"hurling\", \"fraid\", \"sIUgHmzwyWSb\") + \"fKVheqdB\").knack2();" fullword ascii
    $s7  = "atrocity = atrocity+ innovation.shift();" fullword ascii
    $s8  = "String.prototype.knack4 = function() {" fullword ascii
    $s9  = "            andros[mechanical]((\"edition\",\"cooperative\",\"G\" + weasel) + (\"preclude\",\"beech\",\"adjustments\",\"comments" ascii
    $s10 = "String.prototype.knack = function () {" fullword ascii
    $s11 = "String.prototype.knack2 = function () {" fullword ascii
    $s12 = "            andros[mechanical]((\"edition\",\"cooperative\",\"G\" + weasel) + (\"preclude\",\"beech\",\"adjustments\",\"comments" ascii
    $s13 = "        biblical[(manipulate + \"o\"+(\"harbour\",\"basic\",\"shark\",\"therapy\",\"attempting\",\"himalayas\",\"understood\",\"" ascii
    $s14 = "        biblical[(manipulate + \"o\"+(\"harbour\",\"basic\",\"shark\",\"therapy\",\"attempting\",\"himalayas\",\"understood\",\"" ascii
    $s15 = "for (var i in diameter){whomsoever = whomsoever.replace(i, diameter[i]);}" fullword ascii
    $s16 = "var diameter = {" fullword ascii
    $s17 = "whomsoever = this;" fullword ascii
    $s18 = "var cloud = 0;" fullword ascii
    $s19 = "incisive = \"_F2_\";" fullword ascii
    $s20 = "var warble = \"QWnikonN0aXZnikonlWE9ianikonmVjdA=nikon=\".knack4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}