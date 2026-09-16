rule TTP_XOR_QUAD_CurrentVersionRun_9fde {
  strings:
    $key_9fde = { cc b1 [2] e8 bf [2] c3 93 [2] ed b1 [2] f9 aa [2] f6 b0 [2] e8 ad [2] ea ac [2] f1 aa [2] ed ad [2] f1 82 }

  condition:
    any of them
}