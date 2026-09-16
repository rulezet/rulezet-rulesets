rule TTP_XOR_QUAD_CurrentVersionRun_71de {
  strings:
    $key_71de = { 22 b1 [2] 06 bf [2] 2d 93 [2] 03 b1 [2] 17 aa [2] 18 b0 [2] 06 ad [2] 04 ac [2] 1f aa [2] 03 ad [2] 1f 82 }

  condition:
    any of them
}