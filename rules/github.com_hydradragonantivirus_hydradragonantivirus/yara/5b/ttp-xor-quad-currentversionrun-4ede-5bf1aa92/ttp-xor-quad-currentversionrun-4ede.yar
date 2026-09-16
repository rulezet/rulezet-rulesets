rule TTP_XOR_QUAD_CurrentVersionRun_4ede {
  strings:
    $key_4ede = { 1d b1 [2] 39 bf [2] 12 93 [2] 3c b1 [2] 28 aa [2] 27 b0 [2] 39 ad [2] 3b ac [2] 20 aa [2] 3c ad [2] 20 82 }

  condition:
    any of them
}