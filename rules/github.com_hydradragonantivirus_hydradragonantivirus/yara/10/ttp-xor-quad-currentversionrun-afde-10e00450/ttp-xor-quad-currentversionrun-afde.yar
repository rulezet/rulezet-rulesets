rule TTP_XOR_QUAD_CurrentVersionRun_afde {
  strings:
    $key_afde = { fc b1 [2] d8 bf [2] f3 93 [2] dd b1 [2] c9 aa [2] c6 b0 [2] d8 ad [2] da ac [2] c1 aa [2] dd ad [2] c1 82 }

  condition:
    any of them
}