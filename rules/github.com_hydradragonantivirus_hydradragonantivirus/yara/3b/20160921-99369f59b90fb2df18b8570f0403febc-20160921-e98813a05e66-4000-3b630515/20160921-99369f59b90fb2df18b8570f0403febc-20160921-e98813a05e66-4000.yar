rule _20160921_99369f59b90fb2df18b8570f0403febc_20160921_e98813a05e66_4000 {
  meta:
    description = "datamaliciousorder - from files 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "nction f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s2 = "urn \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(" ascii
    $s3 = "h\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s5 = "(function f000(){return \"PTi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"YTp\";})(),(function f000(){" ascii
    $s6 = "ion f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}