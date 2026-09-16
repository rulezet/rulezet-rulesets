rule TTP_XOR_QUAD_CurrentVersionRun_1768 {
  strings:
    $key_1768 = { 44 07 [2] 60 09 [2] 4b 25 [2] 65 07 [2] 71 1c [2] 7e 06 [2] 60 1b [2] 62 1a [2] 79 1c [2] 65 1b [2] 79 34 }

  condition:
    any of them
}