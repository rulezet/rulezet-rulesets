rule TTP_XOR_QUAD_CurrentVersionRun_7bc5 {
  strings:
    $key_7bc5 = { 28 aa [2] 0c a4 [2] 27 88 [2] 09 aa [2] 1d b1 [2] 12 ab [2] 0c b6 [2] 0e b7 [2] 15 b1 [2] 09 b6 [2] 15 99 }

  condition:
    any of them
}