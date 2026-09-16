rule TTP_XOR_QUAD_CurrentVersionRun_f204 {
  strings:
    $key_f204 = { a1 6b [2] 85 65 [2] ae 49 [2] 80 6b [2] 94 70 [2] 9b 6a [2] 85 77 [2] 87 76 [2] 9c 70 [2] 80 77 [2] 9c 58 }

  condition:
    any of them
}