rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160922_f0d656e55be0_5533 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sj0\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s3 = "n f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"M" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"DIa\";" ascii
    $s5 = "eturn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"TRc\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}