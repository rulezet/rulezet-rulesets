rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_aa105be6eeb7_5370 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = "(),(function f000(){return \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"XTn\";})(),(function f000(" ascii
    $s2 = "eturn \"OMd\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii
    $s3 = "tion f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s4 = "ction f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){retu" ascii
    $s5 = "turn \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}