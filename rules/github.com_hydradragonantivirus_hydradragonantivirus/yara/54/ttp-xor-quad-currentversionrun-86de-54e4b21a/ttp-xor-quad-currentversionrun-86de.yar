rule TTP_XOR_QUAD_CurrentVersionRun_86de {
  strings:
    $key_86de = { d5 b1 [2] f1 bf [2] da 93 [2] f4 b1 [2] e0 aa [2] ef b0 [2] f1 ad [2] f3 ac [2] e8 aa [2] f4 ad [2] e8 82 }

  condition:
    any of them
}