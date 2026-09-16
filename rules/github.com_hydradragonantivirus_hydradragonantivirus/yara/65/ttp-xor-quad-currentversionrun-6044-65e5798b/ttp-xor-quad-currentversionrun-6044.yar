rule TTP_XOR_QUAD_CurrentVersionRun_6044 {
  strings:
    $key_6044 = { 33 2b [2] 17 25 [2] 3c 09 [2] 12 2b [2] 06 30 [2] 09 2a [2] 17 37 [2] 15 36 [2] 0e 30 [2] 12 37 [2] 0e 18 }

  condition:
    any of them
}