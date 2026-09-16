rule TTP_XOR_QUAD_CurrentVersionRun_6713 {
  strings:
    $key_6713 = { 34 7c [2] 10 72 [2] 3b 5e [2] 15 7c [2] 01 67 [2] 0e 7d [2] 10 60 [2] 12 61 [2] 09 67 [2] 15 60 [2] 09 4f }

  condition:
    any of them
}