rule TTP_XOR_QUAD_CurrentVersionRun_1e4c {
  strings:
    $key_1e4c = { 4d 23 [2] 69 2d [2] 42 01 [2] 6c 23 [2] 78 38 [2] 77 22 [2] 69 3f [2] 6b 3e [2] 70 38 [2] 6c 3f [2] 70 10 }

  condition:
    any of them
}