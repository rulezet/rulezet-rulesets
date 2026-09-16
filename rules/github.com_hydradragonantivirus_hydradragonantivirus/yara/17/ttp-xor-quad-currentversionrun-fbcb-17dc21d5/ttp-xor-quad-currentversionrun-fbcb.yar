rule TTP_XOR_QUAD_CurrentVersionRun_fbcb {
  strings:
    $key_fbcb = { a8 a4 [2] 8c aa [2] a7 86 [2] 89 a4 [2] 9d bf [2] 92 a5 [2] 8c b8 [2] 8e b9 [2] 95 bf [2] 89 b8 [2] 95 97 }

  condition:
    any of them
}