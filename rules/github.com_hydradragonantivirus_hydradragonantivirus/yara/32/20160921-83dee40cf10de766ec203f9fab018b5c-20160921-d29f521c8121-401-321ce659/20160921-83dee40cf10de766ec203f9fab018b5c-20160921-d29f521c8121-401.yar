rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160921_d29f521c8121_401 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1  = "unction f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){ret" ascii
    $s2  = "ction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){retur" ascii
    $s3  = "Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\";})(),(function" ascii
    $s4  = "tion f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s5  = "unction f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){ret" ascii
    $s6  = "){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(" ascii
    $s7  = "0(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\"" ascii
    $s8  = "){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})" ascii
    $s9  = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function" ascii
    $s10 = "eturn \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s11 = "00(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";" ascii
    $s12 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s13 = "function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s14 = "unction f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s15 = "\"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s16 = " \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s17 = "rn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s18 = "urn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s19 = "ion f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return " ascii
    $s20 = "(){return \"DAp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}