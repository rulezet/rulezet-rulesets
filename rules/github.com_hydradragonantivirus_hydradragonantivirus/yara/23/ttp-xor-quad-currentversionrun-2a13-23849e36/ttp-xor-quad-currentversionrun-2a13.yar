rule TTP_XOR_QUAD_CurrentVersionRun_2a13 {
  strings:
    $key_2a13 = { 79 7c [2] 5d 72 [2] 76 5e [2] 58 7c [2] 4c 67 [2] 43 7d [2] 5d 60 [2] 5f 61 [2] 44 67 [2] 58 60 [2] 44 4f }

  condition:
    any of them
}