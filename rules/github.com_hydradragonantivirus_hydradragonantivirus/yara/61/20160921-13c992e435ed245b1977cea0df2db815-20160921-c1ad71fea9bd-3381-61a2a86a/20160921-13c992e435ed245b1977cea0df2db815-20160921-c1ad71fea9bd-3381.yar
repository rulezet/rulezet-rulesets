rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_c1ad71fea9bd_3381 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "\"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"DIa\";})(),(funct" ascii
    $s2 = " f000(){return \"Go\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GG" ascii
    $s3 = "000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh" ascii
    $s4 = "ion f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = "function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){r" ascii
    $s6 = "n \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}