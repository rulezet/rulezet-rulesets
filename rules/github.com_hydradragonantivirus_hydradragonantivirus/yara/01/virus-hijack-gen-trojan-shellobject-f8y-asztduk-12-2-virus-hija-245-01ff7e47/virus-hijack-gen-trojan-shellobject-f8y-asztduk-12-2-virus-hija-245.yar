rule _Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_12_2_Virus_Hija_245 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_6_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34e2a6e460e8c621b808310b38123fee90c86ea6bd2901186eb28bb6d46779c2"
    hash2       = "78453ca03e85996f563c24334b7987839841faa678cebab3614c9047691413f3"
    hash3       = "c4a54806789b3b99a4e9457c388c159645c2faa7e12f43594e180cff9005ad84"

  strings:
    $s1  = "Failed to get token's elevation information." fullword wide
    $s2  = "::LookupAccountNameW failed to retrieve size of account security identifier (systemname=%s, accountname=%s)." fullword wide
    $s3  = "::LookupAccountNameW failed to retrieve account security identifier (systemname=%s, accountname=%s)." fullword wide
    $s4  = "Get current logon sid here" fullword wide
    $s5  = "@Failed to get current username." fullword wide
    $s6  = "Get impersonated user sid here" fullword wide
    $s7  = "Failed to convert sid to string sid" fullword wide
    $s8  = "@This OEvent object is already initialized" fullword wide
    $s9  = ")Rich!*" fullword ascii
    $s10 = "unexpected appInfo flag" fullword wide
    $s11 = "unexpected sidType flag" fullword wide
    $s12 = "@Cannot wait for object that has invalid handle" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}