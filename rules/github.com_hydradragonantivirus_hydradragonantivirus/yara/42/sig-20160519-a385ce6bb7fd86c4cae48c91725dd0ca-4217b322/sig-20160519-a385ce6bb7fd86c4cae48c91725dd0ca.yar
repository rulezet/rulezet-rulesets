rule sig_20160519_a385ce6bb7fd86c4cae48c91725dd0ca {
  meta:
    description = "datamaliciousorder - file 20160519_a385ce6bb7fd86c4cae48c91725dd0ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3250158ae98491d9a1c8a1910f1159e076ee79374cf93e2e51f996f69859b526"

  strings:
    $s1  = "var cells = [assiduously, aerial,complement,  \"\"+\".\"+(\"implement\",\"bicycles\",\"intolerant\",\"clustered\",\"academic\"," ascii
    $s2  = "weasel = ((\"steeple\", \"north\", \"inserted\", \"aboriginal\", \"EngKKev\") + \"jIBHSvJa\").subscriptions2();" fullword ascii
    $s3  = "debater = ((\"situation\", \"lincolnshire\", \"attachments\", \"exuberant\", \"pAdBdRE\") + \"pqzwTFMwgBs\").subscriptions2();" fullword ascii
    $s4  = "String.prototype.subscriptions = function () {" fullword ascii
    $s5  = "        unhealthy[\"d3JpdGU=\".subscriptions4()](horrible[(\"tahiti\",\"technology\",\"accounting\",\"chase\",\"instructional\"," ascii
    $s6  = "String.prototype.subscriptions4 = function() {" fullword ascii
    $s7  = "var complement =\"JVlightRFTVlightAl\".subscriptions4();" fullword ascii
    $s8  = "String.prototype.subscriptions2 = function () {" fullword ascii
    $s9  = "var aerial =\"RXhwYW5lightkRW52aXlightJvbm1lbnRTdHJlightpbmdz\".subscriptions4();" fullword ascii
    $s10 = "var assiduously = \"QWlightN0aXZlightlWE9ialightmVjdA=light=\".subscriptions4();" fullword ascii
    $s11 = "var forum=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".subscriptions4())&&horrible[\"c3RhdHVz\".subscriptions4()] +\"\"==\"Mj" ascii
    $s12 = "promptly = \"b3Blbg==\".subscriptions4();;" fullword ascii
    $s13 = "var forum=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".subscriptions4())&&horrible[\"c3RhdHVz\".subscriptions4()] +\"\"==\"Mj" ascii
    $s14 = "        unhealthy[(debater + \"o\"+(\"purveyor\",\"shant\",\"harrow\",\"harvest\",\"disinherit\",\"istanbul\",\"released\",\"bro" ascii
    $s15 = "        unhealthy[\"d3JpdGU=\".subscriptions4()](horrible[(\"tahiti\",\"technology\",\"accounting\",\"chase\",\"instructional\"," ascii
    $s16 = "var reading = motels[cells.shift()](cells.shift());" fullword ascii
    $s17 = "        var hypnotized = reading + \"/\" + findings ;" fullword ascii
    $s18 = "var motels = new adhesion(concepts[1]);" fullword ascii
    $s19 = "var adhesion = this[cells.shift()];" fullword ascii
    $s20 = "var horrible = new adhesion(concepts[0]);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}