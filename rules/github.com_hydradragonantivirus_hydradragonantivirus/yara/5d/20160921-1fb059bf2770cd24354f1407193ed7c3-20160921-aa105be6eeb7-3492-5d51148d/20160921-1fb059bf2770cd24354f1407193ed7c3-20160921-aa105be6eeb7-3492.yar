rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_aa105be6eeb7_3492 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = "\"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(func" ascii
    $s2 = "\"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(funct" ascii
    $s3 = "{return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";}" ascii
    $s4 = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f00" ascii
    $s5 = "nction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){retu" ascii
    $s6 = "urn \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}