rule TTP_XOR_QUAD_CurrentVersionRun_7913 {
  strings:
    $key_7913 = { 2a 7c [2] 0e 72 [2] 25 5e [2] 0b 7c [2] 1f 67 [2] 10 7d [2] 0e 60 [2] 0c 61 [2] 17 67 [2] 0b 60 [2] 17 4f }

  condition:
    any of them
}