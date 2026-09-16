rule TTP_XOR_QUAD_CurrentVersionRun_1e1d {
  strings:
    $key_1e1d = { 4d 72 [2] 69 7c [2] 42 50 [2] 6c 72 [2] 78 69 [2] 77 73 [2] 69 6e [2] 6b 6f [2] 70 69 [2] 6c 6e [2] 70 41 }

  condition:
    any of them
}