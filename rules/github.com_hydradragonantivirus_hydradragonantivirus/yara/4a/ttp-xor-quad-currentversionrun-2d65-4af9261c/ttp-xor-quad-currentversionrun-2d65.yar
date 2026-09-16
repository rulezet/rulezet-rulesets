rule TTP_XOR_QUAD_CurrentVersionRun_2d65 {
  strings:
    $key_2d65 = { 7e 0a [2] 5a 04 [2] 71 28 [2] 5f 0a [2] 4b 11 [2] 44 0b [2] 5a 16 [2] 58 17 [2] 43 11 [2] 5f 16 [2] 43 39 }

  condition:
    any of them
}