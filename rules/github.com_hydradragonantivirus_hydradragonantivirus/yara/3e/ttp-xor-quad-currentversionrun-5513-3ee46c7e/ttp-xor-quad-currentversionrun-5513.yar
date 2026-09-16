rule TTP_XOR_QUAD_CurrentVersionRun_5513 {
  strings:
    $key_5513 = { 06 7c [2] 22 72 [2] 09 5e [2] 27 7c [2] 33 67 [2] 3c 7d [2] 22 60 [2] 20 61 [2] 3b 67 [2] 27 60 [2] 3b 4f }

  condition:
    any of them
}