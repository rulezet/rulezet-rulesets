rule TTP_XOR_QUAD_CurrentVersionRun_6141 {
  strings:
    $key_6141 = { 32 2e [2] 16 20 [2] 3d 0c [2] 13 2e [2] 07 35 [2] 08 2f [2] 16 32 [2] 14 33 [2] 0f 35 [2] 13 32 [2] 0f 1d }

  condition:
    any of them
}