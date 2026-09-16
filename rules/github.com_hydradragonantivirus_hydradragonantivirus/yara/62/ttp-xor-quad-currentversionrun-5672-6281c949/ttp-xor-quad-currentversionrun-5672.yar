rule TTP_XOR_QUAD_CurrentVersionRun_5672 {
  strings:
    $key_5672 = { 05 1d [2] 21 13 [2] 0a 3f [2] 24 1d [2] 30 06 [2] 3f 1c [2] 21 01 [2] 23 00 [2] 38 06 [2] 24 01 [2] 38 2e }

  condition:
    any of them
}