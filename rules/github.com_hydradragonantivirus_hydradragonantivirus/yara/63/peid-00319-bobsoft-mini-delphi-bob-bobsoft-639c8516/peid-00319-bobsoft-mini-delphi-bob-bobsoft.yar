rule PEiD_00319_BobSoft_Mini_Delphi____BoB___BobSoft_ {
  meta:
    description = "[BobSoft Mini Delphi -> BoB / BobSoft]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 F0 B8 ?? ?? ?? ?? E8 }

  condition:
    $a
}