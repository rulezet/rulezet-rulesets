import "pe"
rule PEiD_01609_Pelles_C_2_x_4_x_DLL____Pelle_Orinius_ {
  meta:
    description = "[Pelles C 2.x-4.x DLL -> Pelle Orinius]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 53 56 57 8B 5D 0C 8B 75 10 }

  condition:
    $a at pe.entry_point
}