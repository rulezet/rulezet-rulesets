rule TTP_XOR_QUAD_CurrentVersionRun_2d13 {
  strings:
    $key_2d13 = { 7e 7c [2] 5a 72 [2] 71 5e [2] 5f 7c [2] 4b 67 [2] 44 7d [2] 5a 60 [2] 58 61 [2] 43 67 [2] 5f 60 [2] 43 4f }

  condition:
    any of them
}