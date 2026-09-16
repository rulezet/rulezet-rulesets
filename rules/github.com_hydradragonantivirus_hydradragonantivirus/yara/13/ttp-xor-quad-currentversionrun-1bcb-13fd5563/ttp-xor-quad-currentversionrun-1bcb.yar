rule TTP_XOR_QUAD_CurrentVersionRun_1bcb {
  strings:
    $key_1bcb = { 48 a4 [2] 6c aa [2] 47 86 [2] 69 a4 [2] 7d bf [2] 72 a5 [2] 6c b8 [2] 6e b9 [2] 75 bf [2] 69 b8 [2] 75 97 }

  condition:
    any of them
}