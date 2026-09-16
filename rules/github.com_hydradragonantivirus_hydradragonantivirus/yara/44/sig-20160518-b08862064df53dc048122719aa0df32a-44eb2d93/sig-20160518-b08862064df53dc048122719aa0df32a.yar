rule sig_20160518_b08862064df53dc048122719aa0df32a {
  meta:
    description = "datamaliciousorder - file 20160518_b08862064df53dc048122719aa0df32a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5128b78be17ef0657240397fb792e0a48150fb7fe78458a250fcaafdc9cb9a8"

  strings:
    $s1  = "var lingerie=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".zones4())&&incidence[\"c3RhdHVz\".zones4()] +\"\"==\"MjAw\".zones4(" ascii
    $s2  = "var lingerie=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".zones4())&&incidence[\"c3RhdHVz\".zones4()] +\"\"==\"MjAw\".zones4(" ascii
    $s3  = "var mainstream = [confidant, organizer,trudge,  \"\"+\".\"+(\"institutes\",\"bought\",\"ivory\",\"concourse\",\"arizona\",\"groc" ascii
    $s4  = "reality = ((\"stunning\", \"emerging\", \"dependence\", \"lading\", \"psPdFSqsS\") + \"iuBSUpSUs\").zones2();" fullword ascii
    $s5  = "chosen = chosen+ mainstream.shift();" fullword ascii
    $s6  = "weasel = ((\"draper\", \"noontide\", \"partakes\", \"maintains\", \"ETaLuCx\") + \"tRrEMzvOjI\").zones2();" fullword ascii
    $s7  = "String.prototype.zones2 = function () {" fullword ascii
    $s8  = "String.prototype.zones4 = function() {" fullword ascii
    $s9  = "String.prototype.zones = function () {" fullword ascii
    $s10 = "        indigo[(reality + \"o\"+(\"credence\",\"mountebank\",\"schemes\",\"loads\",\"configuration\",\"february\",\"illimitable" ascii
    $s11 = "var incidence = new justin(menus[0]);" fullword ascii
    $s12 = "var babble = 0;" fullword ascii
    $s13 = "helpful = ((\"languish\", \"casuistry\", \"lancet\", \"wound\", \"sKoRlWLSEX\") + \"bsaJBqB\").zones2();" fullword ascii
    $s14 = "conditions = this;" fullword ascii
    $s15 = "var abnegation = new justin(menus[1]);" fullword ascii
    $s16 = "var trudge =\"JVcobwebRFTVcobwebAl\".zones4();" fullword ascii
    $s17 = "var fellow = 6/6;" fullword ascii
    $s18 = "abnegation[mainstream.shift()](chosen, fellow, true);" fullword ascii
    $s19 = "var confidant = \"QWcobwebN0aXZcobweblWE9iacobwebmVjdA=cobweb=\".zones4();" fullword ascii
    $s20 = "ian\",\"webshots\",\"revulsion\",\"currency\",\"checking\",\"sherman\",\"08\"), helpful)] = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}