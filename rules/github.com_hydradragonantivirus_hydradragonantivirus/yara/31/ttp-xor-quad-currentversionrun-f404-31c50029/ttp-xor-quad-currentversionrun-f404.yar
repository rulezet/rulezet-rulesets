rule TTP_XOR_QUAD_CurrentVersionRun_f404 {
  strings:
    $key_f404 = { a7 6b [2] 83 65 [2] a8 49 [2] 86 6b [2] 92 70 [2] 9d 6a [2] 83 77 [2] 81 76 [2] 9a 70 [2] 86 77 [2] 9a 58 }

  condition:
    any of them
}