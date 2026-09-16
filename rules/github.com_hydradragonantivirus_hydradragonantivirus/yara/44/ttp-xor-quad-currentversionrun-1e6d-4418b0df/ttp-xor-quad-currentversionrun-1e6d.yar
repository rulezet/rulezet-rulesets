rule TTP_XOR_QUAD_CurrentVersionRun_1e6d {
  strings:
    $key_1e6d = { 4d 02 [2] 69 0c [2] 42 20 [2] 6c 02 [2] 78 19 [2] 77 03 [2] 69 1e [2] 6b 1f [2] 70 19 [2] 6c 1e [2] 70 31 }

  condition:
    any of them
}