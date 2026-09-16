rule TTP_XOR_QUAD_CurrentVersionRun_7b2b {
  strings:
    $key_7b2b = { 28 44 [2] 0c 4a [2] 27 66 [2] 09 44 [2] 1d 5f [2] 12 45 [2] 0c 58 [2] 0e 59 [2] 15 5f [2] 09 58 [2] 15 77 }

  condition:
    any of them
}