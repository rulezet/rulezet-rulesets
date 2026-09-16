rule TTP_XOR_QUAD_CurrentVersionRun_2d17 {
  strings:
    $key_2d17 = { 7e 78 [2] 5a 76 [2] 71 5a [2] 5f 78 [2] 4b 63 [2] 44 79 [2] 5a 64 [2] 58 65 [2] 43 63 [2] 5f 64 [2] 43 4b }

  condition:
    any of them
}