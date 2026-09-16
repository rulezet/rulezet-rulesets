import "pe"
rule _PEArmor_v07x__Hying_ {
  meta:
    description = "PE-Armor v0.7x -> Hying"

  strings:
    $0 = { 60 E8 00 00 00 00 5D 81 ED ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 55 56 }

  condition:
    $0 at pe.entry_point
}