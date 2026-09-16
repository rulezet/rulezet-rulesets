rule _20160921_619a314e9bcca286c046dff250b54b6b_20160921_6d18600f3019_1880 {
  meta:
    description = "datamaliciousorder - from files 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"

  strings:
    $s1  = "on f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s2  = ",(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s3  = " \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(funct" ascii
    $s4  = "\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f" ascii
    $s5  = "rn \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s6  = "n f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"V" ascii
    $s7  = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"R" ascii
    $s8  = " \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s9  = "00(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";" ascii
    $s10 = "0(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}