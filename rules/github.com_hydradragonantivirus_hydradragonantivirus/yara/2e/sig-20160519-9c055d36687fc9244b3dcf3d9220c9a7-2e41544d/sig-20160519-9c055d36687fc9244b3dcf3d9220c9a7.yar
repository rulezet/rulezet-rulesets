rule sig_20160519_9c055d36687fc9244b3dcf3d9220c9a7 {
  meta:
    description = "datamaliciousorder - file 20160519_9c055d36687fc9244b3dcf3d9220c9a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f741ce48a90fa2166693f3ff27ed3db36625b8ecfa7925baedbf5c8e223052"

  strings:
    $s1  = "var lesbian = [furze, compilation,briton,  \"\"+\".\"+(\"catering\",\"penury\",\"costs\",\"numeric\",\"harmonize\",\"payments\"," ascii
    $s2  = "        share[(houseless + \"o\"+(\"threefold\",\"alicia\",\"probity\",\"baste\",\"fossil\",\"combat\",\"phoenix\",\"clerk\",\"0" ascii
    $s3  = "houseless = ((\"sweets\", \"services\", \"salvage\", \"occupied\", \"pIfCIJwlocx\") + \"xNlihE\").plagiarism2();" fullword ascii
    $s4  = "var reprove=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".plagiarism4())&&unattractive[\"c3RhdHVz\".plagiarism4()] +\"\"==\"Mj" ascii
    $s5  = "var reprove=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".plagiarism4())&&unattractive[\"c3RhdHVz\".plagiarism4()] +\"\"==\"Mj" ascii
    $s6  = "function immigrants(stationery, induction) {" fullword ascii
    $s7  = "var circumspect = new foray(intact[1]);" fullword ascii
    $s8  = "        share[(houseless + \"o\"+(\"threefold\",\"alicia\",\"probity\",\"baste\",\"fossil\",\"combat\",\"phoenix\",\"clerk\",\"0" ascii
    $s9  = "weasel = ((\"metropolitan\", \"meddlesome\", \"dramatist\", \"diego\", \"EuAmmrmiJC\") + \"wVTwWq\").plagiarism2();" fullword ascii
    $s10 = "intimate = ((\"alter\", \"massachusetts\", \"unopened\", \"bombard\", \"technique\", \"currants\", \"sKinCIFN\") + \"yTbIpkc\")." ascii
    $s11 = "String.prototype.plagiarism = function () {" fullword ascii
    $s12 = "  binary = [];" fullword ascii
    $s13 = "var intact = lesbian.pop().split(\">\");" fullword ascii
    $s14 = "var compilation =\"RXhwYW5accessedkRW52aXaccessedJvbm1lbnRTdHJaccessedpbmdz\".plagiarism4();" fullword ascii
    $s15 = "String.prototype.plagiarism2 = function () {" fullword ascii
    $s16 = "String.prototype.plagiarism4 = function() {" fullword ascii
    $s17 = "importune = \"_F2_\";" fullword ascii
    $s18 = "            unattractive[aback]((\"compliance\",\"climber\",\"G\" + weasel) + (\"outdoors\",\"sickened\",\"interaction\",\"compl" ascii
    $s19 = "      binary[ i ] = -1;" fullword ascii
    $s20 = "    unattractive[intimate + (\"commodity\",\"garbage\",\"end\")]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}