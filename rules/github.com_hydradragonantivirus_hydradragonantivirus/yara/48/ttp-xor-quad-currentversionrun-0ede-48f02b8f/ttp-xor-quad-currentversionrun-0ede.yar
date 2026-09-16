rule TTP_XOR_QUAD_CurrentVersionRun_0ede {
  strings:
    $key_0ede = { 5d b1 [2] 79 bf [2] 52 93 [2] 7c b1 [2] 68 aa [2] 67 b0 [2] 79 ad [2] 7b ac [2] 60 aa [2] 7c ad [2] 60 82 }

  condition:
    any of them
}