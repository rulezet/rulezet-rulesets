rule TTP_XOR_QUAD_CurrentVersionRun_0bc5 {
  strings:
    $key_0bc5 = { 58 aa [2] 7c a4 [2] 57 88 [2] 79 aa [2] 6d b1 [2] 62 ab [2] 7c b6 [2] 7e b7 [2] 65 b1 [2] 79 b6 [2] 65 99 }

  condition:
    any of them
}