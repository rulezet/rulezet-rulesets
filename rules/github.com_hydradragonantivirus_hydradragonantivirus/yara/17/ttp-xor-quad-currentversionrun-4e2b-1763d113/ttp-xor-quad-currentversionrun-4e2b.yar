rule TTP_XOR_QUAD_CurrentVersionRun_4e2b {
  strings:
    $key_4e2b = { 1d 44 [2] 39 4a [2] 12 66 [2] 3c 44 [2] 28 5f [2] 27 45 [2] 39 58 [2] 3b 59 [2] 20 5f [2] 3c 58 [2] 20 77 }

  condition:
    any of them
}