rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_989b05bf7416_3411 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "{return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})" ascii
    $s2 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f0" ascii
    $s3 = "(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";" ascii
    $s4 = "ction f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){retu" ascii
    $s5 = "),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){r" ascii
    $s6 = "(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}