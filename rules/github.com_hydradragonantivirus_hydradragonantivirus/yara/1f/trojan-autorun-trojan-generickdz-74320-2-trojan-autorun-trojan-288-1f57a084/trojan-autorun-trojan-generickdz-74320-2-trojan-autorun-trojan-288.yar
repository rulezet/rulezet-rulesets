import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_74320_2_Trojan_Autorun_Trojan__288 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.74320_2.vir, Trojan.Autorun_Trojan.GenericKDZ.74320_27.vir, Trojan.Danger_Trojan.GenericKD.72853156_318_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_323_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_324_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfdbab85abc6359dd930a51758e8a12ad261b2f7d8b9e119584fdc25fef00e19"
    hash2       = "86cb3a6e06c0faa5c1f55f737e49b3467ad2ffa1411668fe41883dad784015ae"
    hash3       = "5142d662f14bdc2f69c3639ec3e7c45584ad927bb8e7378379b91852d9675378"
    hash4       = "bc418c294abab3552cb3937b0191d71d7e7ba77cd7d6ba366c9d39ce5d238f77"
    hash5       = "f24b6e17978cd0c5b77f1bdaec4d07f5453e7f693fb79dc61880d92efeb0f872"

  strings:
    $x1 = "file:///C:/Users/user/AppData/Local/Temp/Sysqemthuyc.exe" fullword wide
    $s2 = ":\\Users\\user\\AppData\\Roaming\\Microsoft\\Internet Explorer\\Quick Launch" fullword wide
    $s3 = "9E3995AB-1F9C-4F13-B827-48B24B6C7174}\\TaskBar\\Windows Media Player.lnk" fullword wide
    $s4 = "shell:::{26EE0668-A00A-44D7-9371-BEB064C98683}\\0\\::{15eae92e-f17a-4431-9f28-805e482dafd4}" fullword wide
    $s5 = "Microsoft\\Windows Photo Gallery\\Original Images" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d3cbd6e8f81da85f6bf0529e69de9251" and (1 of ($x*) and all of them)
    ) or (all of them)
}