rule TTP_XOR_QUAD_CurrentVersionRun_f415 {
  strings:
    $key_f415 = { a7 7a [2] 83 74 [2] a8 58 [2] 86 7a [2] 92 61 [2] 9d 7b [2] 83 66 [2] 81 67 [2] 9a 61 [2] 86 66 [2] 9a 49 }

  condition:
    any of them
}