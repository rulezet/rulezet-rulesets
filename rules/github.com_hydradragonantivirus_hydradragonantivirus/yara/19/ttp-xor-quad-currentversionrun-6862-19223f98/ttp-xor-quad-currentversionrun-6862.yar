rule TTP_XOR_QUAD_CurrentVersionRun_6862 {
  strings:
    $key_6862 = { 3b 0d [2] 1f 03 [2] 34 2f [2] 1a 0d [2] 0e 16 [2] 01 0c [2] 1f 11 [2] 1d 10 [2] 06 16 [2] 1a 11 [2] 06 3e }

  condition:
    any of them
}