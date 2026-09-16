rule TTP_XOR_QUAD_CurrentVersionRun_1e4a {
  strings:
    $key_1e4a = { 4d 25 [2] 69 2b [2] 42 07 [2] 6c 25 [2] 78 3e [2] 77 24 [2] 69 39 [2] 6b 38 [2] 70 3e [2] 6c 39 [2] 70 16 }

  condition:
    any of them
}