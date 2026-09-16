rule TTP_XOR_QUAD_CurrentVersionRun_3fde {
  strings:
    $key_3fde = { 6c b1 [2] 48 bf [2] 63 93 [2] 4d b1 [2] 59 aa [2] 56 b0 [2] 48 ad [2] 4a ac [2] 51 aa [2] 4d ad [2] 51 82 }

  condition:
    any of them
}