import "pe"
rule _Turbo_Pascal_v55_Unit_ {
  meta:
    description = "Turbo Pascal v5.5 Unit"

  strings:
    $0 = { 54 50 55 36 00 }

  condition:
    $0 at pe.entry_point
}