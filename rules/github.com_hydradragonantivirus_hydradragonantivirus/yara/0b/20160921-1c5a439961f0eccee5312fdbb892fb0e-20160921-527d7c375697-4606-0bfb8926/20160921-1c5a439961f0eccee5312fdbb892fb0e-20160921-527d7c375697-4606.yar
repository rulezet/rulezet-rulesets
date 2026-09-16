rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_527d7c375697_4606 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_527d7c3756974f804734da343b6b6f0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"

  strings:
    $s1 = "){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";}" ascii
    $s2 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s3 = "\"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(funct" ascii
    $s4 = "u\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function" ascii
    $s5 = "unction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}