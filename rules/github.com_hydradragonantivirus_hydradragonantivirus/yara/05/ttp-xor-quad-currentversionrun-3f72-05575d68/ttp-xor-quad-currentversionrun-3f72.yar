rule TTP_XOR_QUAD_CurrentVersionRun_3f72 {
  strings:
    $key_3f72 = { 6c 1d [2] 48 13 [2] 63 3f [2] 4d 1d [2] 59 06 [2] 56 1c [2] 48 01 [2] 4a 00 [2] 51 06 [2] 4d 01 [2] 51 2e }

  condition:
    any of them
}