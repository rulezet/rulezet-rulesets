rule PEiD_03376_Vx__Doom_666_ {
  meta:
    description = "[Vx: Doom.666]"
    ep_only     = "true"

  strings:
    $a = { E8 ?? ?? ?? 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B ?? ?? 0E 1F 81 C6 ?? ?? BF ?? ?? B9 ?? ?? FC F3 A4 06 1F 06 B8 ?? ?? 50 CB B4 48 BB 2C 00 CD 21 }

  condition:
    $a
}