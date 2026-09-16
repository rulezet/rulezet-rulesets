rule TTP_XOR_QUAD_CurrentVersionRun_4213 {
  strings:
    $key_4213 = { 11 7c [2] 35 72 [2] 1e 5e [2] 30 7c [2] 24 67 [2] 2b 7d [2] 35 60 [2] 37 61 [2] 2c 67 [2] 30 60 [2] 2c 4f }

  condition:
    any of them
}