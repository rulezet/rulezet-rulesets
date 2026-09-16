rule TTP_XOR_QUAD_CurrentVersionRun_4176 {
  strings:
    $key_4176 = { 12 19 [2] 36 17 [2] 1d 3b [2] 33 19 [2] 27 02 [2] 28 18 [2] 36 05 [2] 34 04 [2] 2f 02 [2] 33 05 [2] 2f 2a }

  condition:
    any of them
}