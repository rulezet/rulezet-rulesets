rule PEiD_02258_Thinstall_Embedded_V2_422_V2_428____Jitit___Sign_by_fly_ {
  meta:
    description = "[Thinstall Embedded V2.422-V2.428 -> Jitit ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 ?? ?? ?? ?? 81 75 04 ?? ?? ?? ?? 81 75 08 ?? ?? ?? ?? 81 75 0C ?? ?? ?? ?? 81 75 10 }

  condition:
    $a
}