rule _20160921_4cda342a49d7c489fce63509619cc08e_20160921_88a4a74b87ab_5136 {
  meta:
    description = "datamaliciousorder - from files 20160921_4cda342a49d7c489fce63509619cc08e.js, 20160921_88a4a74b87ab9fd3fb3dd307f9d7213d.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cabf2bed3c4b1c46c86905c48d0ce38dc15e155546fd36ce4d681314485c6aeb"
    hash2       = "33ff531b193580829a3217137df52750b8df810994123bd1d02bfced3fa6c2ce"
    hash3       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash4       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1 = "ion fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s2 = "\"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(functi" ascii
    $s3 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})" ascii
    $s4 = "k(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\"" ascii
    $s5 = "nction fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}