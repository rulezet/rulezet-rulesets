rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160922_b22dda4c9fbc_952 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1  = "ction f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){retur" ascii
    $s2  = "ction f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return " ascii
    $s3  = "n \"Do\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(func" ascii
    $s4  = "0(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn" ascii
    $s5  = "nction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s6  = "0(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";" ascii
    $s7  = "),(function f000(){return \"Km\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){r" ascii
    $s8  = "00(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s9  = " \"TKp\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s10 = "eturn \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s11 = "0(){return \"Sj\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";" ascii
    $s12 = "000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs" ascii
    $s13 = ",(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){" ascii
    $s14 = "n f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s15 = ";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f0" ascii
    $s16 = "function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){r" ascii
    $s17 = "rn \"Vj\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s18 = "000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Nx\"" ascii
    $s19 = "DNa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s20 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sq\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}