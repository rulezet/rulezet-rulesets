rule sig_20160518_e6090352603ff7d2976c526ab9e013ef {
  meta:
    description = "datamaliciousorder - file 20160518_e6090352603ff7d2976c526ab9e013ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0066208565408078ce51036a6e9987816427d69b377adae1bada673844d885ce"

  strings:
    $s1  = "var abaft = [execration, angola,advance,  \"\"+\".\"+(\"write\",\"hight\",\"notion\",\"sluggard\",\"buildings\",\"gaslight\",\"s" ascii
    $s2  = "var execration = \"QWravennaN0aXZravennalWE9iaravennamVjdA=ravenna=\".vagina4();" fullword ascii
    $s3  = "var abaft = [execration, angola,advance,  \"\"+\".\"+(\"write\",\"hight\",\"notion\",\"sluggard\",\"buildings\",\"gaslight\",\"s" ascii
    $s4  = "var overlap=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vagina4())&&magnificent[\"c3RhdHVz\".vagina4()] +\"\"==\"MjAw\".vagi" ascii
    $s5  = "var overlap=(WScript+\"\"==\"V2luZG93cyBTY3JpcHQgSG9zdA==\".vagina4())&&magnificent[\"c3RhdHVz\".vagina4()] +\"\"==\"MjAw\".vagi" ascii
    $s6  = "function passengers(imports, jerusalem) {" fullword ascii
    $s7  = "weasel = ((\"alpha\", \"directory\", \"dallas\", \"yeomanry\", \"EhAqPwUA\") + \"QUrmdcDTgzE\").vagina2();" fullword ascii
    $s8  = "conceptual = ((\"neuter\", \"disease\", \"requital\", \"bolster\", \"pIePXSTMMOwl\") + \"SQwKpPUg\").vagina2();" fullword ascii
    $s9  = "String.prototype.vagina4 = function() {" fullword ascii
    $s10 = "        perforated[(conceptual + \"o\"+(\"advisor\",\"significant\",\"stumped\",\"exceed\",\"cumbersome\",\"swamped\",\"passover" ascii
    $s11 = "String.prototype.vagina = function () {" fullword ascii
    $s12 = "String.prototype.vagina2 = function () {" fullword ascii
    $s13 = "        perforated[(conceptual + \"o\"+(\"advisor\",\"significant\",\"stumped\",\"exceed\",\"cumbersome\",\"swamped\",\"passover" ascii
    $s14 = "            magnificent[sunless]((\"labrador\",\"steamed\",\"G\" + weasel) + (\"later\",\"grande\",\"acetic\",\"museums\",\"T\")" ascii
    $s15 = "            magnificent[sunless]((\"labrador\",\"steamed\",\"G\" + weasel) + (\"later\",\"grande\",\"acetic\",\"museums\",\"T\")" ascii
    $s16 = "sunless = \"b3Blbg==\".vagina4();;" fullword ascii
    $s17 = "minute = this;" fullword ascii
    $s18 = "var bonfire = 6/6;" fullword ascii
    $s19 = "var blanket = this[abaft.shift()];" fullword ascii
    $s20 = "var hunting = 0;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}