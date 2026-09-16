rule TTP_XOR_QUAD_CurrentVersionRun_2d04 {
  strings:
    $key_2d04 = { 7e 6b [2] 5a 65 [2] 71 49 [2] 5f 6b [2] 4b 70 [2] 44 6a [2] 5a 77 [2] 58 76 [2] 43 70 [2] 5f 77 [2] 43 58 }

  condition:
    any of them
}