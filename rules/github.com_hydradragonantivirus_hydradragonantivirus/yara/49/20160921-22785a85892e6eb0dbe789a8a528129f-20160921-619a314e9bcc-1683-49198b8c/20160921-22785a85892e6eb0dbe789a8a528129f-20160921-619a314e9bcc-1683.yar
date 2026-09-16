rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_619a314e9bcc_1683 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_619a314e9bcca286c046dff250b54b6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"

  strings:
    $s1  = "turn \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})()" ascii
    $s2  = ",(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s3  = "turn \"KDh\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(" ascii
    $s4  = "n f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return " ascii
    $s5  = "n f000(){return \"PTs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"M" ascii
    $s6  = " \"Vj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(functi" ascii
    $s7  = "),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s8  = "ion f000(){return \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return " ascii
    $s9  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s10 = "\"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(functi" ascii
    $s11 = "nction f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}