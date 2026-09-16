rule TTP_XOR_QUAD_CurrentVersionRun_4713 {
  strings:
    $key_4713 = { 14 7c [2] 30 72 [2] 1b 5e [2] 35 7c [2] 21 67 [2] 2e 7d [2] 30 60 [2] 32 61 [2] 29 67 [2] 35 60 [2] 29 4f }

  condition:
    any of them
}