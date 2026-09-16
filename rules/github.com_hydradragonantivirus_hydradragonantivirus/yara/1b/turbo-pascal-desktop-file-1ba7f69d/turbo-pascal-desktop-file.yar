import "pe"
rule _Turbo_Pascal_Desktop_File_ {
  meta:
    description = "Turbo Pascal Desktop File"

  strings:
    $0 = "Turbo Pascal Desktop"

  condition:
    $0 at pe.entry_point
}