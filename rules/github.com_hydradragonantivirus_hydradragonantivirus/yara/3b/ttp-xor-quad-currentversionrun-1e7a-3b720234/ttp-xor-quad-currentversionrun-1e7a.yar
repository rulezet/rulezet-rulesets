rule TTP_XOR_QUAD_CurrentVersionRun_1e7a {
  strings:
    $key_1e7a = { 4d 15 [2] 69 1b [2] 42 37 [2] 6c 15 [2] 78 0e [2] 77 14 [2] 69 09 [2] 6b 08 [2] 70 0e [2] 6c 09 [2] 70 26 }

  condition:
    any of them
}