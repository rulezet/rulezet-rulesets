rule TTP_XOR_QUAD_CurrentVersionRun_4bc5 {
  strings:
    $key_4bc5 = { 18 aa [2] 3c a4 [2] 17 88 [2] 39 aa [2] 2d b1 [2] 22 ab [2] 3c b6 [2] 3e b7 [2] 25 b1 [2] 39 b6 [2] 25 99 }

  condition:
    any of them
}