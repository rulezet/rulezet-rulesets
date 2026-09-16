rule TTP_XOR_QUAD_CurrentVersionRun_5872 {
  strings:
    $key_5872 = { 0b 1d [2] 2f 13 [2] 04 3f [2] 2a 1d [2] 3e 06 [2] 31 1c [2] 2f 01 [2] 2d 00 [2] 36 06 [2] 2a 01 [2] 36 2e }

  condition:
    any of them
}