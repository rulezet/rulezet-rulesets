rule PEiD_02065_Shegerd_Dongle_V4_78____MS_Co__ {
  meta:
    description = "[Shegerd Dongle V4.78 -> MS.Co.]"
    ep_only     = "true"

  strings:
    $a = { E8 32 00 00 00 B8 ?? ?? ?? ?? 8B 18 C1 CB 05 89 DA 36 8B 4C 24 0C }

  condition:
    $a
}