rule TTP_XOR_QUAD_CurrentVersionRun_d9de {
  strings:
    $key_d9de = { 8a b1 [2] ae bf [2] 85 93 [2] ab b1 [2] bf aa [2] b0 b0 [2] ae ad [2] ac ac [2] b7 aa [2] ab ad [2] b7 82 }

  condition:
    any of them
}