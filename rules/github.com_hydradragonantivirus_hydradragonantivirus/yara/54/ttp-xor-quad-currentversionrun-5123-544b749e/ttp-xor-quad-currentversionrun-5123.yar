rule TTP_XOR_QUAD_CurrentVersionRun_5123 {
  strings:
    $key_5123 = { 02 4c [2] 26 42 [2] 0d 6e [2] 23 4c [2] 37 57 [2] 38 4d [2] 26 50 [2] 24 51 [2] 3f 57 [2] 23 50 [2] 3f 7f }

  condition:
    any of them
}