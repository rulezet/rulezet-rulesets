rule TTP_XOR_QUAD_CurrentVersionRun_7c13 {
  strings:
    $key_7c13 = { 2f 7c [2] 0b 72 [2] 20 5e [2] 0e 7c [2] 1a 67 [2] 15 7d [2] 0b 60 [2] 09 61 [2] 12 67 [2] 0e 60 [2] 12 4f }

  condition:
    any of them
}