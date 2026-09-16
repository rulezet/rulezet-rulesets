rule TTP_XOR_QUAD_CurrentVersionRun_2a78 {
  strings:
    $key_2a78 = { 79 17 [2] 5d 19 [2] 76 35 [2] 58 17 [2] 4c 0c [2] 43 16 [2] 5d 0b [2] 5f 0a [2] 44 0c [2] 58 0b [2] 44 24 }

  condition:
    any of them
}