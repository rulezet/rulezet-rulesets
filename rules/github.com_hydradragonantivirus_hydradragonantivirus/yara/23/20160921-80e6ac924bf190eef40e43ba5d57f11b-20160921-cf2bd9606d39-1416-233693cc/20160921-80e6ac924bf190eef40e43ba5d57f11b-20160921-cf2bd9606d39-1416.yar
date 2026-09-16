rule _20160921_80e6ac924bf190eef40e43ba5d57f11b_20160921_cf2bd9606d39_1416 {
  meta:
    description = "datamaliciousorder - from files 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1  = "){return \"OUx\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})" ascii
    $s2  = "})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(function f0" ascii
    $s3  = "eturn \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4  = "unction f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s5  = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})()" ascii
    $s6  = "tion f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return" ascii
    $s7  = "){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZGq\";}" ascii
    $s8  = "function f000(){return \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(f" ascii
    $s10 = "on f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s11 = "\"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt\";})(),(func" ascii
    $s12 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"" ascii
    $s13 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZGq\";})(),(functio" ascii
    $s14 = "rn \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}