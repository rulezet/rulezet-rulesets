rule PEiD_01767_Private_exe_Protector_V2_0____SetiSoft_Team___Sign_by_fly_ {
  meta:
    description = "[Private exe Protector V2.0 -> SetiSoft Team ! Sign by fly]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 }

  condition:
    $a
}