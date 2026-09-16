rule TTP_XOR_QUAD_CurrentVersionRun_1ede {
  strings:
    $key_1ede = { 4d b1 [2] 69 bf [2] 42 93 [2] 6c b1 [2] 78 aa [2] 77 b0 [2] 69 ad [2] 6b ac [2] 70 aa [2] 6c ad [2] 70 82 }

  condition:
    any of them
}