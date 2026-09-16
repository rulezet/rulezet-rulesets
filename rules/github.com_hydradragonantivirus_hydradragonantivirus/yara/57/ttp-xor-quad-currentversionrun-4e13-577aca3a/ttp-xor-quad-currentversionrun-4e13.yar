rule TTP_XOR_QUAD_CurrentVersionRun_4e13 {
  strings:
    $key_4e13 = { 1d 7c [2] 39 72 [2] 12 5e [2] 3c 7c [2] 28 67 [2] 27 7d [2] 39 60 [2] 3b 61 [2] 20 67 [2] 3c 60 [2] 20 4f }

  condition:
    any of them
}