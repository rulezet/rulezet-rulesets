rule TTP_XOR_QUAD_CurrentVersionRun_2fde {
  strings:
    $key_2fde = { 7c b1 [2] 58 bf [2] 73 93 [2] 5d b1 [2] 49 aa [2] 46 b0 [2] 58 ad [2] 5a ac [2] 41 aa [2] 5d ad [2] 41 82 }

  condition:
    any of them
}