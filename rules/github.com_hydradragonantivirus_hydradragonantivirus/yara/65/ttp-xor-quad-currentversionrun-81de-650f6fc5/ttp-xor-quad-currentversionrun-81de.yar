rule TTP_XOR_QUAD_CurrentVersionRun_81de {
  strings:
    $key_81de = { d2 b1 [2] f6 bf [2] dd 93 [2] f3 b1 [2] e7 aa [2] e8 b0 [2] f6 ad [2] f4 ac [2] ef aa [2] f3 ad [2] ef 82 }

  condition:
    any of them
}