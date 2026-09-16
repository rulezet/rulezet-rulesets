rule PEiD_03370_Vx__August_16th__Iron_Maiden__ {
  meta:
    description = "[Vx: August 16th (Iron Maiden)]"
    ep_only     = "true"

  strings:
    $a = { BA 79 02 03 D7 B4 1A CD 21 B8 24 35 CD 21 5F 57 89 9D 4E 02 8C 85 50 02 }

  condition:
    $a
}