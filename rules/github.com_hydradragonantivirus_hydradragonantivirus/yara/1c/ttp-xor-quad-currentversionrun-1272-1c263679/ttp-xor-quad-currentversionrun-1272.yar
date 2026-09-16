rule TTP_XOR_QUAD_CurrentVersionRun_1272 {
  strings:
    $key_1272 = { 41 1d [2] 65 13 [2] 4e 3f [2] 60 1d [2] 74 06 [2] 7b 1c [2] 65 01 [2] 67 00 [2] 7c 06 [2] 60 01 [2] 7c 2e }

  condition:
    any of them
}