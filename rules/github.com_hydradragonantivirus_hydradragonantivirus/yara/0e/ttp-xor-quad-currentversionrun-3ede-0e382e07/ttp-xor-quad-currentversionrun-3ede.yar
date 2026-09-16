rule TTP_XOR_QUAD_CurrentVersionRun_3ede {
  strings:
    $key_3ede = { 6d b1 [2] 49 bf [2] 62 93 [2] 4c b1 [2] 58 aa [2] 57 b0 [2] 49 ad [2] 4b ac [2] 50 aa [2] 4c ad [2] 50 82 }

  condition:
    any of them
}