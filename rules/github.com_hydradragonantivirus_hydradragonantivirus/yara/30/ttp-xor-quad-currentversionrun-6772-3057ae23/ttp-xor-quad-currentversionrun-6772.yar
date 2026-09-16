rule TTP_XOR_QUAD_CurrentVersionRun_6772 {
  strings:
    $key_6772 = { 34 1d [2] 10 13 [2] 3b 3f [2] 15 1d [2] 01 06 [2] 0e 1c [2] 10 01 [2] 12 00 [2] 09 06 [2] 15 01 [2] 09 2e }

  condition:
    any of them
}