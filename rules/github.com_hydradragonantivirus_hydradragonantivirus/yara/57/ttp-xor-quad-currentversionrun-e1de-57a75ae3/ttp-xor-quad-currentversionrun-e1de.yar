rule TTP_XOR_QUAD_CurrentVersionRun_e1de {
  strings:
    $key_e1de = { b2 b1 [2] 96 bf [2] bd 93 [2] 93 b1 [2] 87 aa [2] 88 b0 [2] 96 ad [2] 94 ac [2] 8f aa [2] 93 ad [2] 8f 82 }

  condition:
    any of them
}