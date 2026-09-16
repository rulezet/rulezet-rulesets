rule PEiD_00853_Gamehouse_Media_Protector_Version_Unknown_ {
  meta:
    description = "[Gamehouse Media Protector Version Unknown]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? ?? ?? 6A 00 FF 15 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? 00 00 00 00 00 00 00 00 }

  condition:
    $a
}