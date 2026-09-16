rule TTP_XOR_QUAD_CurrentVersionRun_1fde {
  strings:
    $key_1fde = { 4c b1 [2] 68 bf [2] 43 93 [2] 6d b1 [2] 79 aa [2] 76 b0 [2] 68 ad [2] 6a ac [2] 71 aa [2] 6d ad [2] 71 82 }

  condition:
    any of them
}