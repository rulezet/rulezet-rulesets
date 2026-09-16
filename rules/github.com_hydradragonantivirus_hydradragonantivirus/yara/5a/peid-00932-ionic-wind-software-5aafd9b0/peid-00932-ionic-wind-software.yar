rule PEiD_00932_Ionic_Wind_Software_ {
  meta:
    description = "[Ionic Wind Software]"
    ep_only     = "true"

  strings:
    $a = { 9B DB E3 9B DB E2 D9 2D 00 ?? ?? 00 55 89 E5 E8 }

  condition:
    $a
}