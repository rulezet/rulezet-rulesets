rule PEiD_00921_Inno_Setup_Module_ {
  meta:
    description = "[Inno Setup Module]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF E8 ?? ?? FF FF }

  condition:
    $a
}