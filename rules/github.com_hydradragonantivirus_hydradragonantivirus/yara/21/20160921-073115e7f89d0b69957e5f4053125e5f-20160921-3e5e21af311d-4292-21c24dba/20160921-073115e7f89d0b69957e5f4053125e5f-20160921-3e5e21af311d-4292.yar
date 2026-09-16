rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_3e5e21af311d_4292 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_3e5e21af311d364f73107419b54e74e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "8b6cb861af32c3db5ac97103bfe3b904e62a9eee40ed51764665b556005b9510"

  strings:
    $s1 = "on f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = " f000(){return \"Um\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do" ascii
    $s3 = "\"ZFe\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s4 = "n\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function" ascii
    $s5 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}