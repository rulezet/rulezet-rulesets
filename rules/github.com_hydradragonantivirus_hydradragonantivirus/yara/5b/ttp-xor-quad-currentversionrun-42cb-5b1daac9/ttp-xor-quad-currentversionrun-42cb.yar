rule TTP_XOR_QUAD_CurrentVersionRun_42cb {
  strings:
    $key_42cb = { 11 a4 [2] 35 aa [2] 1e 86 [2] 30 a4 [2] 24 bf [2] 2b a5 [2] 35 b8 [2] 37 b9 [2] 2c bf [2] 30 b8 [2] 2c 97 }

  condition:
    any of them
}