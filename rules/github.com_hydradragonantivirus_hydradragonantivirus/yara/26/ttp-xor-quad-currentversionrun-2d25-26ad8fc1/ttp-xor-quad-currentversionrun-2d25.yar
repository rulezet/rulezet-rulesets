rule TTP_XOR_QUAD_CurrentVersionRun_2d25 {
  strings:
    $key_2d25 = { 7e 4a [2] 5a 44 [2] 71 68 [2] 5f 4a [2] 4b 51 [2] 44 4b [2] 5a 56 [2] 58 57 [2] 43 51 [2] 5f 56 [2] 43 79 }

  condition:
    any of them
}