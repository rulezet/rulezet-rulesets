rule TTP_XOR_QUAD_CurrentVersionRun_4872 {
  strings:
    $key_4872 = { 1b 1d [2] 3f 13 [2] 14 3f [2] 3a 1d [2] 2e 06 [2] 21 1c [2] 3f 01 [2] 3d 00 [2] 26 06 [2] 3a 01 [2] 26 2e }

  condition:
    any of them
}