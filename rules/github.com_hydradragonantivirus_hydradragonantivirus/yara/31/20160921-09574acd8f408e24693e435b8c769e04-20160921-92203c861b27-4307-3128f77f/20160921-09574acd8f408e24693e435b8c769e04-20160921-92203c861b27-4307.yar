rule _20160921_09574acd8f408e24693e435b8c769e04_20160921_92203c861b27_4307 {
  meta:
    description = "datamaliciousorder - from files 20160921_09574acd8f408e24693e435b8c769e04.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502f3f7db781b4ecddec50bed418f60953253591a8d3d5ab1aa2cc3352cd6821"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"

  strings:
    $s1 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"OMd\";})(),(function f0" ascii
    $s2 = "n f000(){return \"Qz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"" ascii
    $s3 = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"PTi\";})(),(fun" ascii
    $s4 = "(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";}" ascii
    $s5 = "000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KX" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}