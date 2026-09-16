rule sig_20160519_de5e175df7414a83af70274ac19da548 {
  meta:
    description = "datamaliciousorder - file 20160519_de5e175df7414a83af70274ac19da548.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eae5efb059ed6fac61ab4399a322cd19e2a7941143c63de153db553d502a8ce6"

  strings:
    $x1  = "var waves = [seacoast, droop,insulin,  \"\"+\".\"+(\"complaints\",\"reilly\",\"transcript\",\"convenient\",\"sophistry\",\"badge" ascii
    $s2  = "weasel = ((\"downloadable\", \"integrating\", \"estimates\", \"miguel\", \"EraWoRJXD\") + \"WIwVAqTHhG\").usurpation2();" fullword ascii
    $s3  = "var waves = [seacoast, droop,insulin,  \"\"+\".\"+(\"complaints\",\"reilly\",\"transcript\",\"convenient\",\"sophistry\",\"badge" ascii
    $s4  = "        kitten[(emanuel + \"o\"+(\"warnings\",\"equity\",\"agonised\",\"accomplishing\",\"consecration\",\"korea\",\"conversely" ascii
    $s5  = "String.prototype.usurpation = function () {" fullword ascii
    $s6  = "var brass = waves.pop().split(\">\");" fullword ascii
    $s7  = "String.prototype.usurpation4 = function() {" fullword ascii
    $s8  = "String.prototype.usurpation2 = function () {" fullword ascii
    $s9  = "        kitten[(emanuel + \"o\"+(\"warnings\",\"equity\",\"agonised\",\"accomplishing\",\"consecration\",\"korea\",\"conversely" ascii
    $s10 = "  exclude = [];" fullword ascii
    $s11 = "var seacoast = \"QWcuckoldN0aXZcuckoldlWE9iacuckoldmVjdA=cuckold=\".usurpation4();" fullword ascii
    $s12 = "for (var i in tolerance){births = births.replace(i, tolerance[i]);}" fullword ascii
    $s13 = "gle, false);" fullword ascii
    $s14 = "sometimes = \"b3Blbg==\".usurpation4();" fullword ascii
    $s15 = "var bewildering = 3-2;  " fullword ascii
    $s16 = "births = this;" fullword ascii
    $s17 = "var busty = new irrigation(brass[0]);" fullword ascii
    $s18 = "yemen[waves.shift()](orleans, bewildering, true);" fullword ascii
    $s19 = "var yemen = new irrigation(brass[1]);" fullword ascii
    $s20 = "var insulin =\"JVcuckoldRFTVcuckoldAl\".usurpation4();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}