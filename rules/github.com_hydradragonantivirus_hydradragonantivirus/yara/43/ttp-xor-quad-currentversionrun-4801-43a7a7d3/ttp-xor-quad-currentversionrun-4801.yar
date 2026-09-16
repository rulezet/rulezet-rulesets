rule TTP_XOR_QUAD_CurrentVersionRun_4801 {
  strings:
    $key_4801 = { 1b 6e [2] 3f 60 [2] 14 4c [2] 3a 6e [2] 2e 75 [2] 21 6f [2] 3f 72 [2] 3d 73 [2] 26 75 [2] 3a 72 [2] 26 5d }

  condition:
    any of them
}