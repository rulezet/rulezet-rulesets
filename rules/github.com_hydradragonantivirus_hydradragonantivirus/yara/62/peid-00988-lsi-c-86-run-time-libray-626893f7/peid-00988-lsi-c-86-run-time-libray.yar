rule PEiD_00988_LSI_C_86_Run_Time_Libray_ {
  meta:
    description = "[LSI C-86 Run-Time Libray]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8E C0 06 17 BC ?? ?? 26 8C ?? ?? ?? B4 30 CD 21 26 A3 ?? ?? FC }

  condition:
    $a
}