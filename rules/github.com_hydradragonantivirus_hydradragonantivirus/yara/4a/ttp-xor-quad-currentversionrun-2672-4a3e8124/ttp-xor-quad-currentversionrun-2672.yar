rule TTP_XOR_QUAD_CurrentVersionRun_2672 {
  strings:
    $key_2672 = { 75 1d [2] 51 13 [2] 7a 3f [2] 54 1d [2] 40 06 [2] 4f 1c [2] 51 01 [2] 53 00 [2] 48 06 [2] 54 01 [2] 48 2e }

  condition:
    any of them
}