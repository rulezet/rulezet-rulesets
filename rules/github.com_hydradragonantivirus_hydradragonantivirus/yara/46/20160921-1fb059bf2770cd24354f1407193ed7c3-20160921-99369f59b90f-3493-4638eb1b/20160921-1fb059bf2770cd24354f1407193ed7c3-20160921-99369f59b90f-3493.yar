rule _20160921_1fb059bf2770cd24354f1407193ed7c3_20160921_99369f59b90f_3493 {
  meta:
    description = "datamaliciousorder - from files 20160921_1fb059bf2770cd24354f1407193ed7c3.js, 20160921_99369f59b90fb2df18b8570f0403febc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca19a6205a8df61781b8acbf540faa9dd7bc11338d9b2e4285541a5ac284f620"
    hash2       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"

  strings:
    $s1 = "urn \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s2 = "000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu" ascii
    $s3 = " \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s4 = "tion f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s6 = "f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"L" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}