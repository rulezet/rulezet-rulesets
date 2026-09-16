rule _Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_6_2_Virus_Hijac_323 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bc8cfe0ad284ff23bdc99affe3e08ffadf35864cf3284b1a4fb16bb27603648"
    hash2       = "637029aea475d17d3a5d368065d16806b1d1c7897b8ed8579706208f6806cf49"

  strings:
    $x1 = "Missing %s property(CommandText does not return a result set{Error creating object.  Please verify that the Microsoft Data Acces" wide
    $s2 = "]Provider=MSDASQL.1;Password=6502;Persist Security Info=True;User ID=host;Data Source=host2000" fullword ascii
    $s3 = "DataSource cannot be changed0Cannot perform this operation on an open dataset\"Dataset not in edit or insert mode1Cannot perform" wide
    $s4 = "Precision<" fullword ascii
    $s5 = "Connected<" fullword ascii
    $s6 = "FROM master" fullword ascii
    $s7 = "SELECT  master_item,master_code " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and all of them)
    ) or (all of them)
}