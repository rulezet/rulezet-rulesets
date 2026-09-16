import "pe"
rule _Free_Pascal_09910_ {
  meta:
    description = "Free Pascal 0.99.10"

  strings:
    $0 = { E8 00 6E 00 00 55 89 E5 8B 7D 0C 8B 75 08 89 F8 8B 5D 10 29 }

  condition:
    $0 at pe.entry_point
}