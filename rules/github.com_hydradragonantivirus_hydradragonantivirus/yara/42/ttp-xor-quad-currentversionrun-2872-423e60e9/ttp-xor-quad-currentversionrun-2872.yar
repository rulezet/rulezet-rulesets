rule TTP_XOR_QUAD_CurrentVersionRun_2872 {
  strings:
    $key_2872 = { 7b 1d [2] 5f 13 [2] 74 3f [2] 5a 1d [2] 4e 06 [2] 41 1c [2] 5f 01 [2] 5d 00 [2] 46 06 [2] 5a 01 [2] 46 2e }

  condition:
    any of them
}