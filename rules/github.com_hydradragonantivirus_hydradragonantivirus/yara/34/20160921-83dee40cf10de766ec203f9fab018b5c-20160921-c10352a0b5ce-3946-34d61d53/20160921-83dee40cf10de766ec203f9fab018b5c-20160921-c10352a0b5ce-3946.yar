rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160921_c10352a0b5ce_3946 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s3 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii
    $s4 = "\"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(funct" ascii
    $s5 = " \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s6 = "function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}