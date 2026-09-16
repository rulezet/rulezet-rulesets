rule TTP_XOR_QUAD_CurrentVersionRun_1f41 {
  strings:
    $key_1f41 = { 4c 2e [2] 68 20 [2] 43 0c [2] 6d 2e [2] 79 35 [2] 76 2f [2] 68 32 [2] 6a 33 [2] 71 35 [2] 6d 32 [2] 71 1d }

  condition:
    any of them
}