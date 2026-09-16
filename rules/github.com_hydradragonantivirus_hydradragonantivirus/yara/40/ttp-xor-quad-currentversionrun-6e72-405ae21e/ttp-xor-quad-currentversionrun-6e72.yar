rule TTP_XOR_QUAD_CurrentVersionRun_6e72 {
  strings:
    $key_6e72 = { 3d 1d [2] 19 13 [2] 32 3f [2] 1c 1d [2] 08 06 [2] 07 1c [2] 19 01 [2] 1b 00 [2] 00 06 [2] 1c 01 [2] 00 2e }

  condition:
    any of them
}