rule TTP_XOR_QUAD_CurrentVersionRun_5441 {
  strings:
    $key_5441 = { 07 2e [2] 23 20 [2] 08 0c [2] 26 2e [2] 32 35 [2] 3d 2f [2] 23 32 [2] 21 33 [2] 3a 35 [2] 26 32 [2] 3a 1d }

  condition:
    any of them
}