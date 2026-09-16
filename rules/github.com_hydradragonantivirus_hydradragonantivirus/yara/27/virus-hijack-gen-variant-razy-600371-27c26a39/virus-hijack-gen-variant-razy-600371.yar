rule Virus_Hijack_Gen_Variant_Razy_600371 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Razy.600371.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf4be610a39477765fd569af7ecff2b41abe1970069bb29f3c26de12dcf72a6f"

  strings:
    $s1 = "Registry access error 0x%1!x!." fullword wide
    $s2 = "You do not have sufficient privileges or the profile on interface \"%1!s!\" is a group policy profile. " fullword wide
    $s3 = "Last trace logs are stored in \"%1!s!\".6Persistent Wired tracing is not enabled on the system..Persistent Wired tracing is curr" wide
    $s4 = "[Failed to add the profile. A group policy profile already exists and cannot be overwritten.g" fullword wide
    $s5 = ".Persistent Wired tracing is currently stopped." fullword wide
    $s6 = "n if you like " fullword ascii
    $s7 = "Not enabled!802.1X authentication not enabled" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}