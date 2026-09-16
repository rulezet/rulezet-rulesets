rule TTP_XOR_QUAD_CurrentVersionRun_1141 {
  strings:
    $key_1141 = { 42 2e [2] 66 20 [2] 4d 0c [2] 63 2e [2] 77 35 [2] 78 2f [2] 66 32 [2] 64 33 [2] 7f 35 [2] 63 32 [2] 7f 1d }

  condition:
    any of them
}