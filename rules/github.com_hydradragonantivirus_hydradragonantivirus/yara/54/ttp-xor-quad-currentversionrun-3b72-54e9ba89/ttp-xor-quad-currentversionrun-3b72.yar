rule TTP_XOR_QUAD_CurrentVersionRun_3b72 {
  strings:
    $key_3b72 = { 68 1d [2] 4c 13 [2] 67 3f [2] 49 1d [2] 5d 06 [2] 52 1c [2] 4c 01 [2] 4e 00 [2] 55 06 [2] 49 01 [2] 55 2e }

  condition:
    any of them
}