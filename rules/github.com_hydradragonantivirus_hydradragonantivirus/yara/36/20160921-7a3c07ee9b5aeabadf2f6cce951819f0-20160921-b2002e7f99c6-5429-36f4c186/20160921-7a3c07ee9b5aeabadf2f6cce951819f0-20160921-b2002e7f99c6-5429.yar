rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_b2002e7f99c6_5429 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"

  strings:
    $s1 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s2 = "n \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s3 = "\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4 = "(function f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){re" ascii
    $s5 = "Lo\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}