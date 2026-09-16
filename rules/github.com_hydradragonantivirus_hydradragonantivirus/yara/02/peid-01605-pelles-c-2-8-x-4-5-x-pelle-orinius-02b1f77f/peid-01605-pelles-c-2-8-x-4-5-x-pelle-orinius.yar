import "pe"
rule PEiD_01605_Pelles_C_2_8_x_4_5_x____Pelle_Orinius_ {
  meta:
    description = "[Pelles C 2.8.x-4.5.x -> Pelle Orinius]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 ?? ?? ?? ?? 64 89 25 ?? ?? ?? ?? 83 EC }

  condition:
    $a at pe.entry_point
}