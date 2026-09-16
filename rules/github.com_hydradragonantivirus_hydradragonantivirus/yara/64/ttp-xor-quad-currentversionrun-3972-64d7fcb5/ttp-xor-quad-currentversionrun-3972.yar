rule TTP_XOR_QUAD_CurrentVersionRun_3972 {
  strings:
    $key_3972 = { 6a 1d [2] 4e 13 [2] 65 3f [2] 4b 1d [2] 5f 06 [2] 50 1c [2] 4e 01 [2] 4c 00 [2] 57 06 [2] 4b 01 [2] 57 2e }

  condition:
    any of them
}