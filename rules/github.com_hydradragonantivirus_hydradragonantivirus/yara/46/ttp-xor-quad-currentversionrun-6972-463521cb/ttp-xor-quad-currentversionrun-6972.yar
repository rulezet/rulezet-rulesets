rule TTP_XOR_QUAD_CurrentVersionRun_6972 {
  strings:
    $key_6972 = { 3a 1d [2] 1e 13 [2] 35 3f [2] 1b 1d [2] 0f 06 [2] 00 1c [2] 1e 01 [2] 1c 00 [2] 07 06 [2] 1b 01 [2] 07 2e }

  condition:
    any of them
}