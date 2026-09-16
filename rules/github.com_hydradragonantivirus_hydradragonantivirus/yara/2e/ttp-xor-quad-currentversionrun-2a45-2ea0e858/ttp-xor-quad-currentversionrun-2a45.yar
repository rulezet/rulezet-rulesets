rule TTP_XOR_QUAD_CurrentVersionRun_2a45 {
  strings:
    $key_2a45 = { 79 2a [2] 5d 24 [2] 76 08 [2] 58 2a [2] 4c 31 [2] 43 2b [2] 5d 36 [2] 5f 37 [2] 44 31 [2] 58 36 [2] 44 19 }

  condition:
    any of them
}