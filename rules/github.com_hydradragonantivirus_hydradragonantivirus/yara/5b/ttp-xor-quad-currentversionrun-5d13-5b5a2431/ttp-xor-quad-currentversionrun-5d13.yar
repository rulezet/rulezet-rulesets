rule TTP_XOR_QUAD_CurrentVersionRun_5d13 {
  strings:
    $key_5d13 = { 0e 7c [2] 2a 72 [2] 01 5e [2] 2f 7c [2] 3b 67 [2] 34 7d [2] 2a 60 [2] 28 61 [2] 33 67 [2] 2f 60 [2] 33 4f }

  condition:
    any of them
}