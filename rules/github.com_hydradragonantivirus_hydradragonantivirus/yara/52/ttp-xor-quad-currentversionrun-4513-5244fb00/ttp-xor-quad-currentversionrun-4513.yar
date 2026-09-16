rule TTP_XOR_QUAD_CurrentVersionRun_4513 {
  strings:
    $key_4513 = { 16 7c [2] 32 72 [2] 19 5e [2] 37 7c [2] 23 67 [2] 2c 7d [2] 32 60 [2] 30 61 [2] 2b 67 [2] 37 60 [2] 2b 4f }

  condition:
    any of them
}