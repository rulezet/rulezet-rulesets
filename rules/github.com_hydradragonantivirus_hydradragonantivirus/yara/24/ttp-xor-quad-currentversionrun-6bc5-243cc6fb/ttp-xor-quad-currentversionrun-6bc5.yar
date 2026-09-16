rule TTP_XOR_QUAD_CurrentVersionRun_6bc5 {
  strings:
    $key_6bc5 = { 38 aa [2] 1c a4 [2] 37 88 [2] 19 aa [2] 0d b1 [2] 02 ab [2] 1c b6 [2] 1e b7 [2] 05 b1 [2] 19 b6 [2] 05 99 }

  condition:
    any of them
}