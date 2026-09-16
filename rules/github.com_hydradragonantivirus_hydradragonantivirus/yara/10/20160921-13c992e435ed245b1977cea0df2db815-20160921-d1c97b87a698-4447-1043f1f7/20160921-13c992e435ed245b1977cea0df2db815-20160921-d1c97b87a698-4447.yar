rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_d1c97b87a698_4447 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1 = "\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s2 = " \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s3 = "})(),(function f000(){return \"Vj\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Tb\";})(),(function f000" ascii
    $s4 = "n \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s5 = "{return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}