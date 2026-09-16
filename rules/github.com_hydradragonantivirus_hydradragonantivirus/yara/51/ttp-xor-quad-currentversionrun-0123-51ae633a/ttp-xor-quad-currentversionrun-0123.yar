rule TTP_XOR_QUAD_CurrentVersionRun_0123 {
  strings:
    $key_0123 = { 52 4c [2] 76 42 [2] 5d 6e [2] 73 4c [2] 67 57 [2] 68 4d [2] 76 50 [2] 74 51 [2] 6f 57 [2] 73 50 [2] 6f 7f }

  condition:
    any of them
}