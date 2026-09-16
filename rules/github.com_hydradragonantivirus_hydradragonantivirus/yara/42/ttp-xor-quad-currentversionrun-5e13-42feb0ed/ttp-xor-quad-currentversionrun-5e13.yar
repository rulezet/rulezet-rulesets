rule TTP_XOR_QUAD_CurrentVersionRun_5e13 {
  strings:
    $key_5e13 = { 0d 7c [2] 29 72 [2] 02 5e [2] 2c 7c [2] 38 67 [2] 37 7d [2] 29 60 [2] 2b 61 [2] 30 67 [2] 2c 60 [2] 30 4f }

  condition:
    any of them
}