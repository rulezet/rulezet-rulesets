import "pe"
rule _Goats_Mutilator_v16__Goat_e0f_ {
  meta:
    description = "Goats Mutilator v1.6 -> Goat/_e0f"

  strings:
    $0 = { E8 E8 01 ?? ?? 60 01 AD B3 27 40 ?? 68 }

  condition:
    $0 at pe.entry_point
}