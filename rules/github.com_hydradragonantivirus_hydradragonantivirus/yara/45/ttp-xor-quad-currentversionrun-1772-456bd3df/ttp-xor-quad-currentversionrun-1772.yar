rule TTP_XOR_QUAD_CurrentVersionRun_1772 {
  strings:
    $key_1772 = { 44 1d [2] 60 13 [2] 4b 3f [2] 65 1d [2] 71 06 [2] 7e 1c [2] 60 01 [2] 62 00 [2] 79 06 [2] 65 01 [2] 79 2e }

  condition:
    any of them
}