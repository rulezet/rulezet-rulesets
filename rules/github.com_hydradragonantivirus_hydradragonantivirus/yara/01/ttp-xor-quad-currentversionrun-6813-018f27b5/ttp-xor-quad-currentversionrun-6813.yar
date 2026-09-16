rule TTP_XOR_QUAD_CurrentVersionRun_6813 {
  strings:
    $key_6813 = { 3b 7c [2] 1f 72 [2] 34 5e [2] 1a 7c [2] 0e 67 [2] 01 7d [2] 1f 60 [2] 1d 61 [2] 06 67 [2] 1a 60 [2] 06 4f }

  condition:
    any of them
}