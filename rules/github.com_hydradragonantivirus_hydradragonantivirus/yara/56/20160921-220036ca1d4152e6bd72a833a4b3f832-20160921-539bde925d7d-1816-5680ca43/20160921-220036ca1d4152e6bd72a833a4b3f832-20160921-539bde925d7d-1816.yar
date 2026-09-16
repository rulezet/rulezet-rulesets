rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_539bde925d7d_1816 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1  = "000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq" ascii
    $s2  = "rn \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s3  = ")(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\";})(),(function f000(" ascii
    $s4  = "on f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s5  = "return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})()" ascii
    $s6  = "(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(function f000(){r" ascii
    $s7  = "n f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"I" ascii
    $s8  = " \"IAa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(funct" ascii
    $s9  = "Gn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function" ascii
    $s10 = "eturn \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}