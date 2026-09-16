rule TTP_XOR_QUAD_CurrentVersionRun_7bcb {
  strings:
    $key_7bcb = { 28 a4 [2] 0c aa [2] 27 86 [2] 09 a4 [2] 1d bf [2] 12 a5 [2] 0c b8 [2] 0e b9 [2] 15 bf [2] 09 b8 [2] 15 97 }

  condition:
    any of them
}