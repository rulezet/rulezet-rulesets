rule _20160921_1c5a439961f0eccee5312fdbb892fb0e_20160921_c1ad71fea9bd_4608 {
  meta:
    description = "datamaliciousorder - from files 20160921_1c5a439961f0eccee5312fdbb892fb0e.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fbb744f5c370c0fc7398db52f2d758d4ee9e8aaf91430daa5c6bada9598710f"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1 = "(function f000(){return \"XTn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){re" ascii
    $s2 = "00(){return \"EZu\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn" ascii
    $s3 = "n f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s4 = " f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s5 = "ction f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}