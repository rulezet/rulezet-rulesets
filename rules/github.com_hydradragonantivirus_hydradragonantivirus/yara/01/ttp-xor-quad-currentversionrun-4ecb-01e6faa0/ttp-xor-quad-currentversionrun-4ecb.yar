rule TTP_XOR_QUAD_CurrentVersionRun_4ecb {
  strings:
    $key_4ecb = { 1d a4 [2] 39 aa [2] 12 86 [2] 3c a4 [2] 28 bf [2] 27 a5 [2] 39 b8 [2] 3b b9 [2] 20 bf [2] 3c b8 [2] 20 97 }

  condition:
    any of them
}