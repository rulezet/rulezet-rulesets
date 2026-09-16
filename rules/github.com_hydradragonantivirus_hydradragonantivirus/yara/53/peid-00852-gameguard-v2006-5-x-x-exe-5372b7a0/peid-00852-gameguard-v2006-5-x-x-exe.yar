import "pe"
rule PEiD_00852_GameGuard_v2006_5_x_x____exe__ {
  meta:
    description = "[GameGuard v2006.5.x.x (*.exe)]"
    ep_only     = "true"

  strings:
    $a = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $a at pe.entry_point
}