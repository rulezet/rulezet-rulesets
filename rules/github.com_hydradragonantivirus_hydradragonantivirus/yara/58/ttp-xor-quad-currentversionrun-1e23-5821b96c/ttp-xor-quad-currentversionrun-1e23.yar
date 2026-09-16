rule TTP_XOR_QUAD_CurrentVersionRun_1e23 {
  strings:
    $key_1e23 = { 4d 4c [2] 69 42 [2] 42 6e [2] 6c 4c [2] 78 57 [2] 77 4d [2] 69 50 [2] 6b 51 [2] 70 57 [2] 6c 50 [2] 70 7f }

  condition:
    any of them
}