rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_92203c861b27_3453 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_92203c861b27f106aadc39fdc2b4c6b7.js, 20160921_c10352a0b5ce476f023184a502920234.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "307c62eb5d0e72645486ed8ab490a017889f28cb40d74f607fae031e9ef250fb"
    hash3       = "661c8aa3c79751c20d118989114b454234f6dbf4ba9604e917fa5191741d3298"

  strings:
    $s1 = "{return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})" ascii
    $s2 = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000" ascii
    $s3 = "urn \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(),(" ascii
    $s4 = " f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Lp" ascii
    $s5 = "tion f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return" ascii
    $s6 = "(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}