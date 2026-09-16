rule PEiD_03479_WWPACK_v3_00__v3_01__Extractable__ {
  meta:
    description = "[WWPACK v3.00, v3.01 (Extractable)]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 6A ?? 06 06 8C D3 83 ?? ?? 53 6A ?? FC }

  condition:
    $a
}