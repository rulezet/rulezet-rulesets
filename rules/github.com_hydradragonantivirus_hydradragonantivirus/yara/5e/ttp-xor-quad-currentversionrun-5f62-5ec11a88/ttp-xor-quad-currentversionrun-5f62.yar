rule TTP_XOR_QUAD_CurrentVersionRun_5f62 {
  strings:
    $key_5f62 = { 0c 0d [2] 28 03 [2] 03 2f [2] 2d 0d [2] 39 16 [2] 36 0c [2] 28 11 [2] 2a 10 [2] 31 16 [2] 2d 11 [2] 31 3e }

  condition:
    any of them
}