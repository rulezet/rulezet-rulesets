rule TTP_XOR_QUAD_CurrentVersionRun_f439 {
  strings:
    $key_f439 = { a7 56 [2] 83 58 [2] a8 74 [2] 86 56 [2] 92 4d [2] 9d 57 [2] 83 4a [2] 81 4b [2] 9a 4d [2] 86 4a [2] 9a 65 }

  condition:
    any of them
}