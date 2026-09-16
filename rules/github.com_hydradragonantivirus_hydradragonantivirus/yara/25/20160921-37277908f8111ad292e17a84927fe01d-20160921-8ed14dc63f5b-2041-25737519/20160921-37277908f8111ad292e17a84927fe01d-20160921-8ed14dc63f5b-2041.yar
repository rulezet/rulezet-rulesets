rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_8ed14dc63f5b_2041 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"

  strings:
    $s1 = "(){return \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";" ascii
    $s2 = "tion f000(){return \"Yi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s3 = "rn \"DNa\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s4 = "rn \"DNa\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s5 = " \"TKl\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s6 = "urn \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"PTs\";})()," ascii
    $s7 = "on f000(){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return " ascii
    $s8 = "0(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";" ascii
    $s9 = "00(){return \"Rh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Br\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}