rule PEiD_00871_HACKSTOP_v1_13_ {
  meta:
    description = "[HACKSTOP v1.13]"
    ep_only     = "true"

  strings:
    $a = { 52 B8 ?? ?? 1E CD 21 86 E0 3D ?? ?? 73 ?? CD 20 0E 1F B4 09 E8 ?? ?? 24 ?? EA }

  condition:
    $a
}