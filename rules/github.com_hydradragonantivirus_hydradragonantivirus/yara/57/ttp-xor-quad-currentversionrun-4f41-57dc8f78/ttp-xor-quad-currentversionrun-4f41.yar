rule TTP_XOR_QUAD_CurrentVersionRun_4f41 {
  strings:
    $key_4f41 = { 1c 2e [2] 38 20 [2] 13 0c [2] 3d 2e [2] 29 35 [2] 26 2f [2] 38 32 [2] 3a 33 [2] 21 35 [2] 3d 32 [2] 21 1d }

  condition:
    any of them
}