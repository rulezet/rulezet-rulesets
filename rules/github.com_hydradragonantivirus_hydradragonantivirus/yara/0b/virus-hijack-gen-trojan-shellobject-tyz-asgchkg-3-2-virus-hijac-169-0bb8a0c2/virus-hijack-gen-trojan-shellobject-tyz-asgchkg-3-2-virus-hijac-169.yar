import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_tyZ_aSgChKg_3_2_Virus_Hijac_169 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.tyZ@aSgChKg_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u4Z@ay8bj9g_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3d972921aa6a40e3546856f91cbb3baecfdc0d17afb2bd4f06aa8873457dfc1"
    hash2       = "e254d31accdb15b7f9d107e66a4f5dac7b73f126e56f809a0ae961bbe8ca1208"

  strings:
    $s1 = "Would you like to disable the debug mode right now? By disabling it you will not be able to create debug logs and send them to o" wide
    $s2 = "s activity will be logged and saved to a file on your disk." fullword wide
    $s3 = "The program is now running in the debug mode. All of the program" fullword wide
    $s4 = "This may reduce the program" fullword wide
    $s5 = "It may have been removed. Please reinstall the application. If the problem persists, contact technical support." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "d7401947d3623a2199a2114d62923cd5" and (all of them)
    ) or (all of them)
}