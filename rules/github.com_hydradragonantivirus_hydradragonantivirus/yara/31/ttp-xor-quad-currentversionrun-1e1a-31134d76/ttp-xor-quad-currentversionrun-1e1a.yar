rule TTP_XOR_QUAD_CurrentVersionRun_1e1a {
  strings:
    $key_1e1a = { 4d 75 [2] 69 7b [2] 42 57 [2] 6c 75 [2] 78 6e [2] 77 74 [2] 69 69 [2] 6b 68 [2] 70 6e [2] 6c 69 [2] 70 46 }

  condition:
    any of them
}