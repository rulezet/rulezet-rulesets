import "pe"
rule PEiD_03413_Vx__Quake_518_ {
  meta:
    description = "[Vx: Quake.518]"
    ep_only     = "true"

  strings:
    $a = { 1E 06 8C C8 8E D8 ?? ?? ?? ?? ?? ?? ?? B8 21 35 CD 21 81 }

  condition:
    $a at pe.entry_point
}