rule TTP_XOR_QUAD_CurrentVersionRun_1e50 {
  strings:
    $key_1e50 = { 4d 3f [2] 69 31 [2] 42 1d [2] 6c 3f [2] 78 24 [2] 77 3e [2] 69 23 [2] 6b 22 [2] 70 24 [2] 6c 23 [2] 70 0c }

  condition:
    any of them
}