rule _20160921_073115e7f89d0b69957e5f4053125e5f_20160921_86391eeb9293_3278 {
  meta:
    description = "datamaliciousorder - from files 20160921_073115e7f89d0b69957e5f4053125e5f.js, 20160921_86391eeb92939f7926213db5cee16e4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1c8736261480d3d6df844d8e7fb92f64f1dc2bf84561d1b707e82daa456fef1"
    hash2       = "1238f360c84929f303678fcd3899297cac43bef18dc5a731b7a6272fde7fe4e6"

  strings:
    $s1 = "on f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"DAp\";})(),(function f000(){return " ascii
    $s2 = " f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WI" ascii
    $s3 = "0(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";}" ascii
    $s4 = "turn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "\"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s6 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}