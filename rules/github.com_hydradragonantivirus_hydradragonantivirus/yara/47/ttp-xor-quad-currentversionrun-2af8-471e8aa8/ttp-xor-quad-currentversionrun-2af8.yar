rule TTP_XOR_QUAD_CurrentVersionRun_2af8 {
  strings:
    $key_2af8 = { 79 97 [2] 5d 99 [2] 76 b5 [2] 58 97 [2] 4c 8c [2] 43 96 [2] 5d 8b [2] 5f 8a [2] 44 8c [2] 58 8b [2] 44 a4 }

  condition:
    any of them
}