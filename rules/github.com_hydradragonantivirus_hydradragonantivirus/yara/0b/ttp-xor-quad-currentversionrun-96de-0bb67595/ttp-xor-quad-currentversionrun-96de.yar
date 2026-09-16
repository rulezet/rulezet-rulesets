rule TTP_XOR_QUAD_CurrentVersionRun_96de {
  strings:
    $key_96de = { c5 b1 [2] e1 bf [2] ca 93 [2] e4 b1 [2] f0 aa [2] ff b0 [2] e1 ad [2] e3 ac [2] f8 aa [2] e4 ad [2] f8 82 }

  condition:
    any of them
}