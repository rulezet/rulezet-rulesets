rule _20160921_058ddf4d10ac7318dd635d4d7f9e6521_20160921_d905978b34be_1323 {
  meta:
    description = "datamaliciousorder - from files 20160921_058ddf4d10ac7318dd635d4d7f9e6521.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beed60d53c1dc194e146ec112b43046bd7ea366584d59483d351cd57e1208385"
    hash2       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1  = "(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";" ascii
    $s2  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(func" ascii
    $s3  = "(function fuck(){return \"Vf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){re" ascii
    $s4  = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(fun" ascii
    $s5  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return " ascii
    $s6  = "unction fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){ret" ascii
    $s7  = "tion fuck(){return \"Yk\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s8  = ",(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s9  = "Vi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(functi" ascii
    $s10 = "{return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})" ascii
    $s11 = " fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"A" ascii
    $s12 = "rn \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(f" ascii
    $s13 = "ction fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s14 = "{return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s15 = "n fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}