rule TTP_XOR_QUAD_CurrentVersionRun_1172 {
  strings:
    $key_1172 = { 42 1d [2] 66 13 [2] 4d 3f [2] 63 1d [2] 77 06 [2] 78 1c [2] 66 01 [2] 64 00 [2] 7f 06 [2] 63 01 [2] 7f 2e }

  condition:
    any of them
}