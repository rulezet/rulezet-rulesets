rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_6ca29d2ebdca_1375 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"

  strings:
    $s1  = "n \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2  = "(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000()" ascii
    $s3  = "function f000(){return \"SGs\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s4  = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb" ascii
    $s5  = "turn \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s6  = "f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s7  = "ion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Rh\";})(),(function f000(){return " ascii
    $s8  = "rn \"MBb\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s9  = "tion f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s10 = " f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s11 = "n \"Wb\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s12 = "n \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s13 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Oe\";})(),(function f000" ascii
    $s14 = "r\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Br\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}