rule TTP_XOR_QUAD_CurrentVersionRun_45ed {
  strings:
    $key_45ed = { 16 82 [2] 32 8c [2] 19 a0 [2] 37 82 [2] 23 99 [2] 2c 83 [2] 32 9e [2] 30 9f [2] 2b 99 [2] 37 9e [2] 2b b1 }

  condition:
    any of them
}