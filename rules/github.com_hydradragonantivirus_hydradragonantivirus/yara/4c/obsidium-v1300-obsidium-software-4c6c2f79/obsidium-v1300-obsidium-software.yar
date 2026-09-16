import "pe"
rule _Obsidium_V1300__Obsidium_Software_ {
  meta:
    description = "Obsidium V1.3.0.0 -> Obsidium Software"

  strings:
    $0 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
    $1 = { EB 04 ?? ?? ?? ?? E8 ?? 00 00 00 }

  condition:
    $0 at pe.entry_point or $1 at pe.entry_point
}