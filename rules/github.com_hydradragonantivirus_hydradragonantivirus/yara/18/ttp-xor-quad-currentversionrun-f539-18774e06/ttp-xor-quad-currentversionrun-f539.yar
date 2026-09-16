rule TTP_XOR_QUAD_CurrentVersionRun_f539 {
  strings:
    $key_f539 = { a6 56 [2] 82 58 [2] a9 74 [2] 87 56 [2] 93 4d [2] 9c 57 [2] 82 4a [2] 80 4b [2] 9b 4d [2] 87 4a [2] 9b 65 }

  condition:
    any of them
}