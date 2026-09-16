rule sig_20160517_73bdd98d3f8b1fc017e1128040046b32 {
  meta:
    description = "datamaliciousorder - file 20160517_73bdd98d3f8b1fc017e1128040046b32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1c65ffdbc70a8441a40b0ce6d45630e4b872f745a8d96e35234416c3d4a5f5f"

  strings:
    $s1  = "forgetful = ((\"oxidation\", \"possible\", \"broadband\", \"boulevard\", \"pPciuYUXhJhD\") + \"tiYUKEGWSnl\").causes2();" fullword ascii
    $s2  = "        screech[(forgetful + \"o\"+(\"amputation\",\"honors\",\"manchu\",\"fixed\",\"training\",\"together\",\"discuss\",\"deuts" ascii
    $s3  = "        screech[(forgetful + \"o\"+(\"amputation\",\"honors\",\"manchu\",\"fixed\",\"training\",\"together\",\"discuss\",\"deuts" ascii
    $s4  = "corolla = corolla+ nourish.shift();" fullword ascii
    $s5  = "var profitless = nourish.pop().split(\"" fullword ascii
    $s6  = "var conduct=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".causes4())&&specialized[\"c3RhdHVz\".causes4()] +\"\"==\"MjAw\".caus" ascii
    $s7  = "var conduct=(\"\"+WScript==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".causes4())&&specialized[\"c3RhdHVz\".causes4()] +\"\"==\"MjAw\".caus" ascii
    $s8  = "closer[nourish.shift()](corolla, organisms, true);nuXEgTmt = \"_F17_\";" fullword ascii
    $s9  = "var nourish = [south, regency,usurped,  \"\"+\".\"+(\"contractors\",\"bodice\",\"sardinia\",\"archives\",\"tipsy\",\"framing\"," ascii
    $s10 = "ggravated\",\"avowal\",\"uncover\",\"indeed\",\"expand\",\"08\"), impervious)] = 0;" fullword ascii
    $s11 = "var nourish = [south, regency,usurped,  \"\"+\".\"+(\"contractors\",\"bodice\",\"sardinia\",\"archives\",\"tipsy\",\"framing\"," ascii
    $s12 = "var specialized = new adventure(profitless[0]);" fullword ascii
    $s13 = "function efforts(those, humanitarian) {" fullword ascii
    $s14 = "weasel = ((\"quilted\", \"winder\", \"mammoth\", \"hating\", \"ENQOFlxsCvNV\") + \"jvlYGKLuupt\").causes2();" fullword ascii
    $s15 = "soviet = \"_F2_\";" fullword ascii
    $s16 = "var adventure = this[nourish.shift()];" fullword ascii
    $s17 = "var sunday = closer[nourish.shift()](nourish.shift());" fullword ascii
    $s18 = "for (var i in thereat){flexibility = flexibility.replace(i, thereat[i]);}" fullword ascii
    $s19 = "var thereat = {" fullword ascii
    $s20 = "var closer = new adventure(profitless[1]);" fullword ascii

  condition:
    uint16(0) == 0x6c4b and
    8 of them
}