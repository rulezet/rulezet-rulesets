rule PEiD_03480_WWPACK_v3_00__v3_01__Relocations_pack__ {
  meta:
    description = "[WWPACK v3.00, v3.01 (Relocations pack)]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }

  condition:
    $a
}