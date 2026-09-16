rule TTP_XOR_QUAD_CurrentVersionRun_4c72 {
  strings:
    $key_4c72 = { 1f 1d [2] 3b 13 [2] 10 3f [2] 3e 1d [2] 2a 06 [2] 25 1c [2] 3b 01 [2] 39 00 [2] 22 06 [2] 3e 01 [2] 22 2e }

  condition:
    any of them
}