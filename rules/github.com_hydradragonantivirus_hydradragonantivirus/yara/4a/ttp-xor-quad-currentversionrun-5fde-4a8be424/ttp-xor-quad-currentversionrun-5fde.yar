rule TTP_XOR_QUAD_CurrentVersionRun_5fde {
  strings:
    $key_5fde = { 0c b1 [2] 28 bf [2] 03 93 [2] 2d b1 [2] 39 aa [2] 36 b0 [2] 28 ad [2] 2a ac [2] 31 aa [2] 2d ad [2] 31 82 }

  condition:
    any of them
}