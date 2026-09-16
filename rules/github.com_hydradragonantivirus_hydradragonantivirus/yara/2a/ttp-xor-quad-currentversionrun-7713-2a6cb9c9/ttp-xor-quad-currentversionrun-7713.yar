rule TTP_XOR_QUAD_CurrentVersionRun_7713 {
  strings:
    $key_7713 = { 24 7c [2] 00 72 [2] 2b 5e [2] 05 7c [2] 11 67 [2] 1e 7d [2] 00 60 [2] 02 61 [2] 19 67 [2] 05 60 [2] 19 4f }

  condition:
    any of them
}