rule _20160921_8621b60975e0be691f97b2f5849011b9_20160921_a1c2a36f9932_365 {
  meta:
    description = "datamaliciousorder - from files 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash2       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash3       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1  = "n \"ZFe\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s2  = "return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})()," ascii
    $s3  = "return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(" ascii
    $s4  = " f000(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw" ascii
    $s5  = "\"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(funct" ascii
    $s6  = "n\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qj\";})(),(function" ascii
    $s7  = "tion f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s8  = "unction f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){retu" ascii
    $s9  = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s10 = "00(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\"" ascii
    $s11 = "){return \"Oh\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})" ascii
    $s12 = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s13 = "return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})()," ascii
    $s14 = "f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz" ascii
    $s15 = "){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";}" ascii
    $s16 = "(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){r" ascii
    $s17 = "00(){return \"WIj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";" ascii
    $s18 = "(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";}" ascii
    $s19 = "WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s20 = "){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}