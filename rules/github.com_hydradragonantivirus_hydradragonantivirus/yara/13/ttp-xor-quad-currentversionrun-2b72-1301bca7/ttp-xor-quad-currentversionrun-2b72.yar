rule TTP_XOR_QUAD_CurrentVersionRun_2b72 {
  strings:
    $key_2b72 = { 78 1d [2] 5c 13 [2] 77 3f [2] 59 1d [2] 4d 06 [2] 42 1c [2] 5c 01 [2] 5e 00 [2] 45 06 [2] 59 01 [2] 45 2e }

  condition:
    any of them
}