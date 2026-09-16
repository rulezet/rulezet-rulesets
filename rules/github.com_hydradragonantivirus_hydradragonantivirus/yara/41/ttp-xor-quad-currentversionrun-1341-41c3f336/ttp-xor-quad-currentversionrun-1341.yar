rule TTP_XOR_QUAD_CurrentVersionRun_1341 {
  strings:
    $key_1341 = { 40 2e [2] 64 20 [2] 4f 0c [2] 61 2e [2] 75 35 [2] 7a 2f [2] 64 32 [2] 66 33 [2] 7d 35 [2] 61 32 [2] 7d 1d }

  condition:
    any of them
}