rule PEiD_01765_Private_exe_Protector_2_15____SetiSoft_Team_ {
  meta:
    description = "[Private exe Protector 2.15 -> SetiSoft Team]"
    ep_only     = "true"

  strings:
    $a = { 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 00 00 00 00 }

  condition:
    $a
}