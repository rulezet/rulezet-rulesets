rule _20160802_a262188ccd1a894b45ad1041592e29cd_20160802_af4e0f399fbb_2179 {
  meta:
    description = "datamaliciousorder - from files 20160802_a262188ccd1a894b45ad1041592e29cd.js, 20160802_af4e0f399fbbada114bb7f1e0e84481f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8cf2dbcd89a5cc63a063cddfb93fd6aa3ff12aa9cb71ff54b7f88e99e42e845"
    hash2       = "1cc2cc3c3e4a772e780e3dacc28f7dad730e878ebe99021c71a5230b637cc091"

  strings:
    $s1 = "+\\x20KJd \\x2b (function IMn(){return CZi8\\x3b}()), Zs5 + Te1 + Su(\\x4d\\x53\\x6c) + Xt6);\\r\\nvar UWy4=Pe0[QSc + (function " ascii
    $s2 = "on SGv(KLy\\x35){return KLy5;};fu\\x6ecti\\x6fn\\x20J\\x51\\x75(K\\x4b\\x684){\\x72eturn \\x4bKh4;};var OXv9\\x20=\\x20\"gt\\x68" ascii
    $s3 = "Ss4\\x20+ If(Kg), Jl9 + CZy + IIk2 \\x2b (function NKy\\x30(){\\x72eturn EYf;}()));\\r\\nvar Te=M\\x7a9[QS\\x63 + OXv9\\x5d;\\r" ascii
    $s4 = " + \"\";\\r\\n\\x66u\\x6ection\\x20If(YBe){return Y\\x42e;};v\\x61r Kg = \"13\\x32\"\\x20+ \\x22\";\\r\\nvar BSs4 = \"1123\" + " ascii
    $s5 = "Mj + (fu\\x6ection O\\x695\\x28){return \\x45Gw;}()) + Dh5 +\\x20Ca8 + (\\x66unction EPo\\x28){ret\\x75\\x72n Wp;}()) + Xc6 + Zb" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}