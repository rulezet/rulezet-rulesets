rule TTP_XOR_QUAD_CurrentVersionRun_4562 {
  strings:
    $key_4562 = { 16 0d [2] 32 03 [2] 19 2f [2] 37 0d [2] 23 16 [2] 2c 0c [2] 32 11 [2] 30 10 [2] 2b 16 [2] 37 11 [2] 2b 3e }

  condition:
    any of them
}