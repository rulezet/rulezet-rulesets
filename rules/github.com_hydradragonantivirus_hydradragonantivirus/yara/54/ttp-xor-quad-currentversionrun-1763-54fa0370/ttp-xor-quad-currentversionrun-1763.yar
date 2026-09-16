rule TTP_XOR_QUAD_CurrentVersionRun_1763 {
  strings:
    $key_1763 = { 44 0c [2] 60 02 [2] 4b 2e [2] 65 0c [2] 71 17 [2] 7e 0d [2] 60 10 [2] 62 11 [2] 79 17 [2] 65 10 [2] 79 3f }

  condition:
    any of them
}