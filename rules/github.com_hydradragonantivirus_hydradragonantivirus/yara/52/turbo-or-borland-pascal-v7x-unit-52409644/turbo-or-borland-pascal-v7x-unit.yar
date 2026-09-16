import "pe"
rule _Turbo_or_Borland_Pascal_v7x_Unit_ {
  meta:
    description = "Turbo or Borland Pascal v7.x Unit"

  strings:
    $0 = { 54 50 55 51 00 }

  condition:
    $0 at pe.entry_point
}