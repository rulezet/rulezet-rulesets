rule _20160921_8ed14dc63f5bac37baa70510a94f2915_20160921_e0f34764de4f_3977 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_e0f34764de4fcb908eef371ab4011f31.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash2       = "de457f8d789ffcd672900ad06037697526230f620a01d113732fa3683b1604b1"

  strings:
    $s1 = "Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s2 = "eturn \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()" ascii
    $s3 = "0(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})" ascii
    $s4 = "eturn \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s5 = "\"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(functio" ascii
    $s6 = "rn \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}