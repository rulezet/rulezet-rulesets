rule TTP_XOR_QUAD_CurrentVersionRun_83de {
  strings:
    $key_83de = { d0 b1 [2] f4 bf [2] df 93 [2] f1 b1 [2] e5 aa [2] ea b0 [2] f4 ad [2] f6 ac [2] ed aa [2] f1 ad [2] ed 82 }

  condition:
    any of them
}