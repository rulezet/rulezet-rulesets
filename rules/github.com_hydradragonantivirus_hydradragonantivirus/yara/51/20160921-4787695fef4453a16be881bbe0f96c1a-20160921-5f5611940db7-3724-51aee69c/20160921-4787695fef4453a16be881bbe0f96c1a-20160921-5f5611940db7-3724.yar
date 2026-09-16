rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_5f5611940db7_3724 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"

  strings:
    $s1 = "on f000(){return \"Tn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "tion f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii
    $s3 = "0(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\"" ascii
    $s4 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sq\";})(),(function f000(" ascii
    $s5 = " \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s6 = "return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sv\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}