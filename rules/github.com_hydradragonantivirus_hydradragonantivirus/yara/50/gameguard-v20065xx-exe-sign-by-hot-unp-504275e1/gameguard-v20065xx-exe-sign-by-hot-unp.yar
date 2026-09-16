import "pe"
rule _GameGuard_v20065xx_exe__sign_by_hot_UNP_ {
  meta:
    description = "GameGuard v2006.5.x.x (*.exe) -> sign by hot_UNP"

  strings:
    $0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE 00 }

  condition:
    $0 at pe.entry_point
}