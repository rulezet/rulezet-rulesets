rule TTP_XOR_QUAD_CurrentVersionRun_7e72 {
  strings:
    $key_7e72 = { 2d 1d [2] 09 13 [2] 22 3f [2] 0c 1d [2] 18 06 [2] 17 1c [2] 09 01 [2] 0b 00 [2] 10 06 [2] 0c 01 [2] 10 2e }

  condition:
    any of them
}