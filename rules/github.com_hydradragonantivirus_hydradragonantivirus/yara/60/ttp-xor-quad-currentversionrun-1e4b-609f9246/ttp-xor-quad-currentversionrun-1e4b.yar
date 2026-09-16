rule TTP_XOR_QUAD_CurrentVersionRun_1e4b {
  strings:
    $key_1e4b = { 4d 24 [2] 69 2a [2] 42 06 [2] 6c 24 [2] 78 3f [2] 77 25 [2] 69 38 [2] 6b 39 [2] 70 3f [2] 6c 38 [2] 70 17 }

  condition:
    any of them
}