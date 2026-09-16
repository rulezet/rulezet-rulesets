rule TTP_XOR_QUAD_CurrentVersionRun_1746 {
  strings:
    $key_1746 = { 44 29 [2] 60 27 [2] 4b 0b [2] 65 29 [2] 71 32 [2] 7e 28 [2] 60 35 [2] 62 34 [2] 79 32 [2] 65 35 [2] 79 1a }

  condition:
    any of them
}