rule TTP_XOR_QUAD_CurrentVersionRun_13c5 {
  strings:
    $key_13c5 = { 40 aa [2] 64 a4 [2] 4f 88 [2] 61 aa [2] 75 b1 [2] 7a ab [2] 64 b6 [2] 66 b7 [2] 7d b1 [2] 61 b6 [2] 7d 99 }

  condition:
    any of them
}