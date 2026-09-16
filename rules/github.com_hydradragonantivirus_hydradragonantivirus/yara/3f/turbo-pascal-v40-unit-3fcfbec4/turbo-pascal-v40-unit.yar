import "pe"
rule _Turbo_Pascal_v40_Unit_ {
  meta:
    description = "Turbo Pascal v4.0 Unit"

  strings:
    $0 = { 54 50 55 30 00 }

  condition:
    $0 at pe.entry_point
}