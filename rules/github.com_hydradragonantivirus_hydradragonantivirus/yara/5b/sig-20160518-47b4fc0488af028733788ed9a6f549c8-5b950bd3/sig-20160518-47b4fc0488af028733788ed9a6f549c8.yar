rule sig_20160518_47b4fc0488af028733788ed9a6f549c8 {
  meta:
    description = "datamaliciousorder - file 20160518_47b4fc0488af028733788ed9a6f549c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e8839daa65a09851ebb1a29278a479696b6690afa4d9135ab36f688c6d331df"

  strings:
    $s1  = "\",\"steak\",\"tomorrow\",\"cr\")+(\"hostage\",\"since\",\"moving\",\"impression\",\"overbearing\",\"patio\",\"dozens\",\"bahama" ascii
    $s2  = "var tinkling = [scraggy, bracelet,bleached,  \"\"+\".\"+(\"suddenly\",\"arbitration\",\"diffusion\",\"sections\",\"naive\",\"hav" ascii
    $s3  = "itly\",\"A\")+(\"london\",\"twentyfourth\",\"poisoning\",\"frankfurt\",\"press\",\"series\",\"idiomatic\",\"diver\",\"SEOO\")+\"" ascii
    $s4  = "weasel = ((\"cursor\", \"serve\", \"apostate\", \"bituminous\", \"EYVgPeFs\") + \"TPAFqXRbt\").sauce2();" fullword ascii
    $s5  = "var density=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sauce4())&&preventive[\"c3RhdHVz\".sauce4()] +\"\"==\"MjAw\".sauce4(" ascii
    $s6  = "var density=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".sauce4())&&preventive[\"c3RhdHVz\".sauce4()] +\"\"==\"MjAw\".sauce4(" ascii
    $s7  = "        poseidon[(shelter + \"o\"+(\"richie\",\"imputation\",\"devel\",\"milton\",\"loiter\",\"nunnery\",\"pushing\",\"upheld\"," ascii
    $s8  = "shelter = ((\"cracking\", \"paraffin\", \"hawaiian\", \"domino\", \"ppPALguJUiKl\") + \"uSlHVBvtWUs\").sauce2();" fullword ascii
    $s9  = "formulate = ((\"corinth\", \"touch\", \"cobra\", \"arroyo\", \"sHnLRwVLpK\") + \"NEooHERrD\").sauce2();" fullword ascii
    $s10 = "var compares = depth[tinkling.shift()](tinkling.shift());" fullword ascii
    $s11 = "var sailing = tinkling.pop().split(\">\");" fullword ascii
    $s12 = "String.prototype.sauce4 = function() {" fullword ascii
    $s13 = "String.prototype.sauce2 = function () {" fullword ascii
    $s14 = "String.prototype.sauce = function () {" fullword ascii
    $s15 = "        var abounded = compares + \"/\" + submissive ;" fullword ascii
    $s16 = "var preventive = new oakland(sailing[0]);" fullword ascii
    $s17 = "small = \"b3Blbg==\".sauce4();;" fullword ascii
    $s18 = "var scraggy = \"QWpeninsulaN0aXZpeninsulalWE9iapeninsulamVjdA=peninsula=\".sauce4();" fullword ascii
    $s19 = "for (var i in prisoners){tricky = tricky.replace(i, prisoners[i]);}" fullword ascii
    $s20 = "tricky = this;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}