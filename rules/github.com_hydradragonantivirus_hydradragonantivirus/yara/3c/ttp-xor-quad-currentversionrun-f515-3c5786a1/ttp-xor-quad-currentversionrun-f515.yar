rule TTP_XOR_QUAD_CurrentVersionRun_f515 {
  strings:
    $key_f515 = { a6 7a [2] 82 74 [2] a9 58 [2] 87 7a [2] 93 61 [2] 9c 7b [2] 82 66 [2] 80 67 [2] 9b 61 [2] 87 66 [2] 9b 49 }

  condition:
    any of them
}