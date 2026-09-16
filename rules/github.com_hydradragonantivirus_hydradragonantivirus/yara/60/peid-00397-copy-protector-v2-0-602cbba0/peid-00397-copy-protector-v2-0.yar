rule PEiD_00397_Copy_Protector_v2_0_ {
  meta:
    description = "[Copy Protector v2.0]"
    ep_only     = "true"

  strings:
    $a = { 2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F }

  condition:
    $a
}