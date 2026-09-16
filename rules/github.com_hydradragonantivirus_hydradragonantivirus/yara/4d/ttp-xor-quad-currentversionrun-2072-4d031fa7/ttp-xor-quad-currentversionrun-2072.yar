rule TTP_XOR_QUAD_CurrentVersionRun_2072 {
  strings:
    $key_2072 = { 73 1d [2] 57 13 [2] 7c 3f [2] 52 1d [2] 46 06 [2] 49 1c [2] 57 01 [2] 55 00 [2] 4e 06 [2] 52 01 [2] 4e 2e }

  condition:
    any of them
}