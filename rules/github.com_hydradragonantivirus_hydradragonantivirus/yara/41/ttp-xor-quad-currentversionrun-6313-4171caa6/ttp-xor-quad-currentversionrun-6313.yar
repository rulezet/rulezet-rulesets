rule TTP_XOR_QUAD_CurrentVersionRun_6313 {
  strings:
    $key_6313 = { 30 7c [2] 14 72 [2] 3f 5e [2] 11 7c [2] 05 67 [2] 0a 7d [2] 14 60 [2] 16 61 [2] 0d 67 [2] 11 60 [2] 0d 4f }

  condition:
    any of them
}