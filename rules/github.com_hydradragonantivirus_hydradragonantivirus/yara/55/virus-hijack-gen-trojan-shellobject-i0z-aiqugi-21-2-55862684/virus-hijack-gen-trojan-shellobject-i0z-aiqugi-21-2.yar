rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_21_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5e53d3fd583ff60776fc6e46e1343a4b9c5661df245328db30e88d269323ff9b"

  strings:
    $s1  = "Failed to get directory metadata for SIS CS path:%ls" fullword wide
    $s2  = "5Wbengine(PID:%ld,TID:%ld) Assertion Failed: %s(%d): %s" fullword ascii
    $s3  = "SOFTWARE\\Microsoft\\Microsoft Data Protection Manager\\Agent\\2.0\\UsnJournal" fullword wide
    $s4  = "SOFTWARE\\Microsoft\\Microsoft Data Protection Manager\\Agent\\2.0" fullword wide
    $s5  = "Failed to find SIS CS file:%ws" fullword wide
    $s6  = "eSystem Volume Information\\UsnForVolume" fullword wide
    $s7  = "pAtomTable != NULL" fullword ascii
    $s8  = "wszOriginalAccessPath != NULL" fullword ascii
    $s9  = "m_SISData.pSISBackupStruct == NULL" fullword ascii
    $s10 = "CHUNKED(m_ulFeatures) == FALSE" fullword ascii
    $s11 = "m_fThrottlingHelperInitialized == true" fullword ascii
    $s12 = "m_wszFileSpecs != NULL" fullword ascii
    $s13 = "((HANDLE)(LONG_PTR)-1) != hFile" fullword ascii
    $s14 = "phFile != NULL" fullword ascii
    $s15 = ";O8m_pEngine == NULL" fullword ascii
    $s16 = "bm_pVolumeCat != NULL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}