rule sig_20160518_6bce3aac183feabb6ffadb6c0845ce33 {
  meta:
    description = "datamaliciousorder - file 20160518_6bce3aac183feabb6ffadb6c0845ce33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84934c46f513f3fb8a694dd9706b47d273c6d2d31dc2ae00727a83677209ba93"

  strings:
    $x1  = "var investing = [icing, prayers,siren,  \"\"+\".\"+(\"contemporaneous\",\"inaccuracy\",\"seems\",\"tourism\",\"nvidia\",\"episod" ascii
    $s2  = "        trademark[(hedgehog + \"o\"+(\"luggage\",\"gamma\",\"postposted\",\"belinda\",\"brittle\",\"genealogy\",\"episodes\",\"w" ascii
    $s3  = "        trademark[(hedgehog + \"o\"+(\"luggage\",\"gamma\",\"postposted\",\"belinda\",\"brittle\",\"genealogy\",\"episodes\",\"w" ascii
    $s4  = "var investing = [icing, prayers,siren,  \"\"+\".\"+(\"contemporaneous\",\"inaccuracy\",\"seems\",\"tourism\",\"nvidia\",\"episod" ascii
    $s5  = "var ellen=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hermitage4())&&waiver[\"c3RhdHVz\".hermitage4()] +\"\"==\"MjAw\".hermi" ascii
    $s6  = "var ellen=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".hermitage4())&&waiver[\"c3RhdHVz\".hermitage4()] +\"\"==\"MjAw\".hermi" ascii
    $s7  = "var pathology = 0;" fullword ascii
    $s8  = "since = since+ investing.shift();" fullword ascii
    $s9  = "weasel = ((\"knife\", \"reliable\", \"mediocrity\", \"wright\", \"ENJyPWmf\") + \"DYbIrqFkzMa\").hermitage2();" fullword ascii
    $s10 = "retention = ((\"annihilation\", \"closest\", \"digestive\", \"spectacular\", \"sspkLJwg\") + \"uoGTQXLtE\").hermitage2();" fullword ascii
    $s11 = "brawn(\"aHR0cDovLw==\".hermitage4()+\"\\u0077\\u0077\\u0077\\u002E\\u0062\\u0072\\u0069\\u0061\\u0072\\u0068\\u0075\\u0072\\u007" ascii
    $s12 = "String.prototype.hermitage2 = function () {" fullword ascii
    $s13 = "String.prototype.hermitage4 = function() {" fullword ascii
    $s14 = "String.prototype.hermitage = function () {" fullword ascii
    $s15 = "baptised\",\"manitoba\",\"painting\",\"compute\",\"prettier\",\"08\"), retention)] = 0;" fullword ascii
    $s16 = "var tradition = 6/6;" fullword ascii
    $s17 = "hedgehog = ((\"tomorrow\", \"current\", \"tradespeople\", \"cakes\", \"pkIpourf\") + \"wQddGXEVin\").hermitage2();" fullword ascii
    $s18 = "var soluble = this[investing.shift()];" fullword ascii
    $s19 = "courtesy = \"_F2_\";" fullword ascii
    $s20 = "    auditor.finding = auditor.restrict[\"c3Vic3RyaW5n\".hermitage4()](pathology, tradition);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}