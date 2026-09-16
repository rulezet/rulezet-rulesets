rule TTP_XOR_QUAD_CurrentVersionRun_1e7c {
  strings:
    $key_1e7c = { 4d 13 [2] 69 1d [2] 42 31 [2] 6c 13 [2] 78 08 [2] 77 12 [2] 69 0f [2] 6b 0e [2] 70 08 [2] 6c 0f [2] 70 20 }

  condition:
    any of them
}