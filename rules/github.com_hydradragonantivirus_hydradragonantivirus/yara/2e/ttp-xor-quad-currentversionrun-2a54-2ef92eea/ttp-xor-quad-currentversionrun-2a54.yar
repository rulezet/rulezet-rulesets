rule TTP_XOR_QUAD_CurrentVersionRun_2a54 {
  strings:
    $key_2a54 = { 79 3b [2] 5d 35 [2] 76 19 [2] 58 3b [2] 4c 20 [2] 43 3a [2] 5d 27 [2] 5f 26 [2] 44 20 [2] 58 27 [2] 44 08 }

  condition:
    any of them
}