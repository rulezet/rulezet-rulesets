rule TTP_XOR_QUAD_CurrentVersionRun_1364 {
  strings:
    $key_1364 = { 40 0b [2] 64 05 [2] 4f 29 [2] 61 0b [2] 75 10 [2] 7a 0a [2] 64 17 [2] 66 16 [2] 7d 10 [2] 61 17 [2] 7d 38 }

  condition:
    any of them
}