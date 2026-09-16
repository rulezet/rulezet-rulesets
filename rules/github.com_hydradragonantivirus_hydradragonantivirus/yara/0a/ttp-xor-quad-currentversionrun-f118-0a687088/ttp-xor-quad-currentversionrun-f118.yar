rule TTP_XOR_QUAD_CurrentVersionRun_f118 {
  strings:
    $key_f118 = { a2 77 [2] 86 79 [2] ad 55 [2] 83 77 [2] 97 6c [2] 98 76 [2] 86 6b [2] 84 6a [2] 9f 6c [2] 83 6b [2] 9f 44 }

  condition:
    any of them
}