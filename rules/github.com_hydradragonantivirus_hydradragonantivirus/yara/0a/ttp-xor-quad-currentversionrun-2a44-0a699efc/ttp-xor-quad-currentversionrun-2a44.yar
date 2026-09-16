rule TTP_XOR_QUAD_CurrentVersionRun_2a44 {
  strings:
    $key_2a44 = { 79 2b [2] 5d 25 [2] 76 09 [2] 58 2b [2] 4c 30 [2] 43 2a [2] 5d 37 [2] 5f 36 [2] 44 30 [2] 58 37 [2] 44 18 }

  condition:
    any of them
}