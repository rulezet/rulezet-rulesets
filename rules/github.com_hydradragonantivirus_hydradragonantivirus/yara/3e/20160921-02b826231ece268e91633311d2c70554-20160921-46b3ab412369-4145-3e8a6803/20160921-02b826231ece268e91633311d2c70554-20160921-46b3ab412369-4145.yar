rule _20160921_02b826231ece268e91633311d2c70554_20160921_46b3ab412369_4145 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash3       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash4       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash5       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash6       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash7       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash8       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash9       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = ",(function f000(){return \"IPu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s2 = "ion f000(){return \"Ml\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return " ascii
    $s3 = "(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(" ascii
    $s4 = "unction f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Uo\";})(),(function f000(){ret" ascii
    $s5 = "(function f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}