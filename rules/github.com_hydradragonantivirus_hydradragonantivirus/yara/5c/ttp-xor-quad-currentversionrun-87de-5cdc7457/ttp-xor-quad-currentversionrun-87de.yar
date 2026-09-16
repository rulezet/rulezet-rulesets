rule TTP_XOR_QUAD_CurrentVersionRun_87de {
  strings:
    $key_87de = { d4 b1 [2] f0 bf [2] db 93 [2] f5 b1 [2] e1 aa [2] ee b0 [2] f0 ad [2] f2 ac [2] e9 aa [2] f5 ad [2] e9 82 }

  condition:
    any of them
}