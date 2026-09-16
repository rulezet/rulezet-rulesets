rule PEiD_01404_Obsidium_V1_2_5_8_V1_3_3_X____Obsidium_Software___Sign_by_fly_ {
  meta:
    description = "[Obsidium V1.2.5.8-V1.3.3.X -> Obsidium Software ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { EB 01 ?? E8 ?? 00 00 00 EB 02 ?? ?? EB }

  condition:
    $a
}