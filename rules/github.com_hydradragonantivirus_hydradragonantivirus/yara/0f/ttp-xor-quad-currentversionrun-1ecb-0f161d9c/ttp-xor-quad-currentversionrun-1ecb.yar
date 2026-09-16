rule TTP_XOR_QUAD_CurrentVersionRun_1ecb {
  strings:
    $key_1ecb = { 4d a4 [2] 69 aa [2] 42 86 [2] 6c a4 [2] 78 bf [2] 77 a5 [2] 69 b8 [2] 6b b9 [2] 70 bf [2] 6c b8 [2] 70 97 }

  condition:
    any of them
}