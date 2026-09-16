rule TTP_XOR_QUAD_CurrentVersionRun_1e2b {
  strings:
    $key_1e2b = { 4d 44 [2] 69 4a [2] 42 66 [2] 6c 44 [2] 78 5f [2] 77 45 [2] 69 58 [2] 6b 59 [2] 70 5f [2] 6c 58 [2] 70 77 }

  condition:
    any of them
}