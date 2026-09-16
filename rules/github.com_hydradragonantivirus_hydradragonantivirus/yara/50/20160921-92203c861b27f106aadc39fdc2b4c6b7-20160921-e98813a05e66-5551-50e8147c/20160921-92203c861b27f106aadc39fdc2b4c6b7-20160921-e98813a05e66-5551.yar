rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_e98813a05e66_5551 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_e98813a05e661b621a9d4b3a1d6d901f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "5b491479317737dd237b9c5bc10e2831e78ae8bbc9ea6a11e5ef5f5bc6c813f8"

  strings:
    $s1 = "RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function" ascii
    $s2 = "000(){return \"QDg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz" ascii
    $s3 = "{return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})" ascii
    $s4 = "(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(" ascii
    $s5 = "n f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}