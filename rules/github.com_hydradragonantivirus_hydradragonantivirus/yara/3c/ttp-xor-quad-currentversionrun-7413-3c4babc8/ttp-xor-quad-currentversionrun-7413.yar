rule TTP_XOR_QUAD_CurrentVersionRun_7413 {
  strings:
    $key_7413 = { 27 7c [2] 03 72 [2] 28 5e [2] 06 7c [2] 12 67 [2] 1d 7d [2] 03 60 [2] 01 61 [2] 1a 67 [2] 06 60 [2] 1a 4f }

  condition:
    any of them
}