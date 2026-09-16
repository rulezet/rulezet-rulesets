rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_daba59e7a6b9_4909 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "on f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s2 = "i\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s3 = "return \"Oh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})()," ascii
    $s4 = "{return \"PTs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s5 = "eturn \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}