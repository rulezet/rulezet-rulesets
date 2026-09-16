rule TTP_XOR_QUAD_CurrentVersionRun_f445 {
  strings:
    $key_f445 = { a7 2a [2] 83 24 [2] a8 08 [2] 86 2a [2] 92 31 [2] 9d 2b [2] 83 36 [2] 81 37 [2] 9a 31 [2] 86 36 [2] 9a 19 }

  condition:
    any of them
}