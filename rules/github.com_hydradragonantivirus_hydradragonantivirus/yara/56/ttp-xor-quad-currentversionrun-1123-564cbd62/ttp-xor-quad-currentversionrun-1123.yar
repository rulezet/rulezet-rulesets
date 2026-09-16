rule TTP_XOR_QUAD_CurrentVersionRun_1123 {
  strings:
    $key_1123 = { 42 4c [2] 66 42 [2] 4d 6e [2] 63 4c [2] 77 57 [2] 78 4d [2] 66 50 [2] 64 51 [2] 7f 57 [2] 63 50 [2] 7f 7f }

  condition:
    any of them
}