rule TTP_XOR_QUAD_CurrentVersionRun_61de {
  strings:
    $key_61de = { 32 b1 [2] 16 bf [2] 3d 93 [2] 13 b1 [2] 07 aa [2] 08 b0 [2] 16 ad [2] 14 ac [2] 0f aa [2] 13 ad [2] 0f 82 }

  condition:
    any of them
}