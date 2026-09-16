rule TTP_XOR_QUAD_CurrentVersionRun_1e20 {
  strings:
    $key_1e20 = { 4d 4f [2] 69 41 [2] 42 6d [2] 6c 4f [2] 78 54 [2] 77 4e [2] 69 53 [2] 6b 52 [2] 70 54 [2] 6c 53 [2] 70 7c }

  condition:
    any of them
}