rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_b7400937fc4e_1864 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"

  strings:
    $s1  = "00(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk" ascii
    $s2  = " f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"M" ascii
    $s3  = " \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s4  = "f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vj" ascii
    $s5  = "Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function" ascii
    $s6  = "){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(" ascii
    $s7  = "(),(function f000(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s8  = "nction f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s9  = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000" ascii
    $s10 = "){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}