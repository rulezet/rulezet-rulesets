rule sig_20160519_e1ce5422e306a5c63a8ab5567246fe70 {
  meta:
    description = "datamaliciousorder - file 20160519_e1ce5422e306a5c63a8ab5567246fe70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21a7f8fdf4172eb6cab2361797c57a3fda8a111e088d7125826da322186dce36"

  strings:
    $s1  = "var istanbul = [arabic, sealskin,turbid,  \"\"+\".\"+(\"sensor\",\"consolidated\",\"royalist\",\"inert\",\"presidential\",\"boob" ascii
    $s2  = "            laugh[unencumbered]((\"amalgamated\",\"acclaim\",\"G\" + weasel) + (\"pervert\",\"proficient\",\"deadened\",\"fucked" ascii
    $s3  = "var illegitimate = istanbul.pop().split(\">\");" fullword ascii
    $s4  = "            laugh[unencumbered]((\"amalgamated\",\"acclaim\",\"G\" + weasel) + (\"pervert\",\"proficient\",\"deadened\",\"fucked" ascii
    $s5  = "        baying[(slavic + \"o\"+(\"wallis\",\"height\",\"lurked\",\"magnitude\",\"worshiped\",\"afternoon\",\"groundwork\",\"equi" ascii
    $s6  = "slang = ((\"kitten\", \"availability\", \"portrayed\", \"optional\", \"cuckold\", \"squeak\", \"sXCIrHTwB\") + \"bsOsjbB\").cava" ascii
    $s7  = "var bellies=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cavalcade4())&&laugh[\"c3RhdHVz\".cavalcade4()] +\"\"==\"MjAw\".cava" ascii
    $s8  = "var bellies=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".cavalcade4())&&laugh[\"c3RhdHVz\".cavalcade4()] +\"\"==\"MjAw\".cava" ascii
    $s9  = "for (var i in hebrides){engineering = engineering.replace(i, hebrides[i]);}" fullword ascii
    $s10 = "weasel = ((\"idaho\", \"abate\", \"leavetaking\", \"dweller\", \"EggrjNU\") + \"qAxOGsVSkCF\").cavalcade2();" fullword ascii
    $s11 = "var ruling = 0;" fullword ascii
    $s12 = "var istanbul = [arabic, sealskin,turbid,  \"\"+\".\"+(\"sensor\",\"consolidated\",\"royalist\",\"inert\",\"presidential\",\"boob" ascii
    $s13 = "erwent\",\"quagmire\",\"dangerous\",\"physicians\",\"08\"), slang)] = 0;" fullword ascii
    $s14 = "var island = new microwave(illegitimate[1]);" fullword ascii
    $s15 = "var laugh = new microwave(illegitimate[0]);" fullword ascii
    $s16 = "var microwave = this[istanbul.shift()];" fullword ascii
    $s17 = "  younger = [];" fullword ascii
    $s18 = "var defects = island[istanbul.shift()](istanbul.shift());" fullword ascii
    $s19 = "engineering = this;" fullword ascii
    $s20 = "aggrandizement = \"_F2_\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}