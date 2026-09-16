rule TTP_XOR_QUAD_CurrentVersionRun_72d1 {
  strings:
    $key_72d1 = { 21 be [2] 05 b0 [2] 2e 9c [2] 00 be [2] 14 a5 [2] 1b bf [2] 05 a2 [2] 07 a3 [2] 1c a5 [2] 00 a2 [2] 1c 8d }

  condition:
    any of them
}