import "pe"
rule _Turbo_Pascal_Configuration_File_ {
  meta:
    description = "Turbo Pascal Configuration File"

  strings:
    $0 = "Turbo Pascal Configuration"

  condition:
    $0 at pe.entry_point
}