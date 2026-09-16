rule TTP_XOR_QUAD_CurrentVersionRun_4166 {
  strings:
    $key_4166 = { 12 09 [2] 36 07 [2] 1d 2b [2] 33 09 [2] 27 12 [2] 28 08 [2] 36 15 [2] 34 14 [2] 2f 12 [2] 33 15 [2] 2f 3a }

  condition:
    any of them
}