rule TTP_XOR_QUAD_CurrentVersionRun_e6de {
  strings:
    $key_e6de = { b5 b1 [2] 91 bf [2] ba 93 [2] 94 b1 [2] 80 aa [2] 8f b0 [2] 91 ad [2] 93 ac [2] 88 aa [2] 94 ad [2] 88 82 }

  condition:
    any of them
}