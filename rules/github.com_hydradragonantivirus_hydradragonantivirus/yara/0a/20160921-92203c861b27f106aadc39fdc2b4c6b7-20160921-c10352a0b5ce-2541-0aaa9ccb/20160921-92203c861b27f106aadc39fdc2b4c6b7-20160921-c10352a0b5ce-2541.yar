rule _20160921_92203c861b27f106aadc39fdc2b4c6b7_20160921_c10352a0b5ce_2541 {
  meta:
    description = "datamaliciousorder - from files 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash2       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Rh\";})(),(function f000(){retur" ascii
    $s2 = "\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s3 = "Yz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(functio" ascii
    $s4 = "(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";}" ascii
    $s5 = "00(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s6 = "(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})(),(function f000(){" ascii
    $s7 = " \"Oe\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(func" ascii
    $s8 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sv\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}