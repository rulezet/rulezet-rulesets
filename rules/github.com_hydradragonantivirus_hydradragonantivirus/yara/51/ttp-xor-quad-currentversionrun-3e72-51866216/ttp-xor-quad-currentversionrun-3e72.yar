rule TTP_XOR_QUAD_CurrentVersionRun_3e72 {
  strings:
    $key_3e72 = { 6d 1d [2] 49 13 [2] 62 3f [2] 4c 1d [2] 58 06 [2] 57 1c [2] 49 01 [2] 4b 00 [2] 50 06 [2] 4c 01 [2] 50 2e }

  condition:
    any of them
}