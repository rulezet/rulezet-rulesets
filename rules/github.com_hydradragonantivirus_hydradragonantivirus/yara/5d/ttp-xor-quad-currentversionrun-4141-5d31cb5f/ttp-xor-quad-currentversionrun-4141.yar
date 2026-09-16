rule TTP_XOR_QUAD_CurrentVersionRun_4141 {
  strings:
    $key_4141 = { 12 2e [2] 36 20 [2] 1d 0c [2] 33 2e [2] 27 35 [2] 28 2f [2] 36 32 [2] 34 33 [2] 2f 35 [2] 33 32 [2] 2f 1d }

  condition:
    any of them
}