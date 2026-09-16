rule TTP_XOR_QUAD_CurrentVersionRun_1e5d {
  strings:
    $key_1e5d = { 4d 32 [2] 69 3c [2] 42 10 [2] 6c 32 [2] 78 29 [2] 77 33 [2] 69 2e [2] 6b 2f [2] 70 29 [2] 6c 2e [2] 70 01 }

  condition:
    any of them
}