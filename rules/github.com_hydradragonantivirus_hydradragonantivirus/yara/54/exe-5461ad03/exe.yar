import "pe"
rule _EXE____ {
  meta:
    description = "ؾEXEļ Աר -> ¾"

  strings:
    $0 = { 55 8B EC 83 C4 E4 53 56 57 33 C0 89 45 E4 89 45 }

  condition:
    $0 at pe.entry_point
}