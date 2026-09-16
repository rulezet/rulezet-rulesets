rule TTP_XOR_QUAD_CurrentVersionRun_3472 {
  strings:
    $key_3472 = { 67 1d [2] 43 13 [2] 68 3f [2] 46 1d [2] 52 06 [2] 5d 1c [2] 43 01 [2] 41 00 [2] 5a 06 [2] 46 01 [2] 5a 2e }

  condition:
    any of them
}