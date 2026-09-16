rule _20160921_83dee40cf10de766ec203f9fab018b5c_20160921_92203c861b27_3067 {
  meta:
    description = "datamaliciousorder - from files 20160921_83dee40cf10de766ec203f9fab018b5c.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_d29f521c8121911a610a80bcc76b94bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash3       = "e80237660128a774d0b2338e2d9c1fb4921908fa1f5ccbf74a87c0a04d0a8667"

  strings:
    $s1 = "nction f000(){return \"IPu\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){retu" ascii
    $s2 = "return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = "{return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(" ascii
    $s4 = ")(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(" ascii
    $s5 = ",(function f000(){return \"Ot\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){re" ascii
    $s6 = "i\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s7 = "unction f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Lp\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}