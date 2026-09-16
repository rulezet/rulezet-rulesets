rule _20160517_20784e561a0c3243afda93ef07ef71e3_20160517_7d28cdb2f52a_1239 {
  meta:
    description = "datamaliciousorder - from files 20160517_20784e561a0c3243afda93ef07ef71e3.js, 20160517_7d28cdb2f52a8720f407ecc69cc63ebe.js, 20160517_e6a7f3255c66d6007e05f9c622dccaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7be84a3e936411e6464e15d1c674cb7e8bce5b68edd7c594646836d857f5fae6"
    hash2       = "283d7fb1ac8f5fce56c8abaaea488c6776e524d2faf038a306fa43f79c661eaf"
    hash3       = "b9cbb5e5ee186c58632d67a3b51db8bdf57d1a234ae0a29ff4acca05c279a346"

  strings:
    $s1 = "function Scott /* a  */(accinp0 /* a  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s2 = "function DENMARK(Turkey) {var devel0 /* a  */ = (123, Turkey); return devel0 /* a  */;};" fullword ascii
    $s3 = "devel1[aaa](Turkey0 /* a  */, Currency, (true, false));" fullword ascii
    $s4 = "DENMARK1 /* a  */= true;/* a  */" fullword ascii
    $s5 = "function Scott /* a  */(accinp0 /* a  */){arrCurrentTag1[(\"@sdf3asdf \", \"adfs3.\", \"R\")+ \"u\" + (\"x\", \"n\")](accinp0 /*" ascii
    $s6 = "place = /* a  */(/* a  */\"noitisop\").split(''/* a  */).reverse(/* a  */).join('');" fullword ascii

  condition:
    (uint16(0) == 0x0a0d and (all of them)
    ) or (all of them)
}