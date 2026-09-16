rule TTP_XOR_QUAD_CurrentVersionRun_94de {
  strings:
    $key_94de = { c7 b1 [2] e3 bf [2] c8 93 [2] e6 b1 [2] f2 aa [2] fd b0 [2] e3 ad [2] e1 ac [2] fa aa [2] e6 ad [2] fa 82 }

  condition:
    any of them
}