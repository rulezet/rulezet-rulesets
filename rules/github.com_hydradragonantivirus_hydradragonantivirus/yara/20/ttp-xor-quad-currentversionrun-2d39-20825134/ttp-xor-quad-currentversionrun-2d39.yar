rule TTP_XOR_QUAD_CurrentVersionRun_2d39 {
  strings:
    $key_2d39 = { 7e 56 [2] 5a 58 [2] 71 74 [2] 5f 56 [2] 4b 4d [2] 44 57 [2] 5a 4a [2] 58 4b [2] 43 4d [2] 5f 4a [2] 43 65 }

  condition:
    any of them
}