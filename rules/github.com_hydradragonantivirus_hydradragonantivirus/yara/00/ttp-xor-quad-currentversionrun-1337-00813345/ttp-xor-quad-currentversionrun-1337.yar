rule TTP_XOR_QUAD_CurrentVersionRun_1337 {
  strings:
    $key_1337 = { 40 58 [2] 64 56 [2] 4f 7a [2] 61 58 [2] 75 43 [2] 7a 59 [2] 64 44 [2] 66 45 [2] 7d 43 [2] 61 44 [2] 7d 6b }

  condition:
    any of them
}