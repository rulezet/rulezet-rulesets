rule TTP_XOR_QUAD_CurrentVersionRun_1777 {
  strings:
    $key_1777 = { 44 18 [2] 60 16 [2] 4b 3a [2] 65 18 [2] 71 03 [2] 7e 19 [2] 60 04 [2] 62 05 [2] 79 03 [2] 65 04 [2] 79 2b }

  condition:
    any of them
}