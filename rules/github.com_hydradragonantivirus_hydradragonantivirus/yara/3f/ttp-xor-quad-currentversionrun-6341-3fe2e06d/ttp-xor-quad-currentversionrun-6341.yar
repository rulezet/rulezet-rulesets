rule TTP_XOR_QUAD_CurrentVersionRun_6341 {
  strings:
    $key_6341 = { 30 2e [2] 14 20 [2] 3f 0c [2] 11 2e [2] 05 35 [2] 0a 2f [2] 14 32 [2] 16 33 [2] 0d 35 [2] 11 32 [2] 0d 1d }

  condition:
    any of them
}