rule _20160921_3941d41b2f7cb84a9ce802558f71cf2e_20160921_f7b964e1d5b6_3652 {
  meta:
    description = "datamaliciousorder - from files 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash2       = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"

  strings:
    $s1 = "00(){return \"Yz\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";" ascii
    $s2 = "Gn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s3 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s4 = " f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GG" ascii
    $s5 = "),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){" ascii
    $s6 = "turn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}