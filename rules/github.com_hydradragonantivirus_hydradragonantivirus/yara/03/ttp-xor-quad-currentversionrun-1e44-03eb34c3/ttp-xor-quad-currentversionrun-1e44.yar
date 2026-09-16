rule TTP_XOR_QUAD_CurrentVersionRun_1e44 {
  strings:
    $key_1e44 = { 4d 2b [2] 69 25 [2] 42 09 [2] 6c 2b [2] 78 30 [2] 77 2a [2] 69 37 [2] 6b 36 [2] 70 30 [2] 6c 37 [2] 70 18 }

  condition:
    any of them
}