rule PEiD_02326_Unknown_Protected_Mode_compiler__2__ {
  meta:
    description = "[Unknown Protected Mode compiler (2)]"
    ep_only     = "true"

  strings:
    $a = { FA FC 0E 1F E8 ?? ?? 8C C0 66 0F B7 C0 66 C1 E0 ?? 66 67 A3 }

  condition:
    $a
}