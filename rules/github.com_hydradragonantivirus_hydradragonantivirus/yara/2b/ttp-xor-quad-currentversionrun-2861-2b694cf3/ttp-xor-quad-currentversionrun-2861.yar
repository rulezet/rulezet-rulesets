rule TTP_XOR_QUAD_CurrentVersionRun_2861 {
  strings:
    $key_2861 = { 7b 0e [2] 5f 00 [2] 74 2c [2] 5a 0e [2] 4e 15 [2] 41 0f [2] 5f 12 [2] 5d 13 [2] 46 15 [2] 5a 12 [2] 46 3d }

  condition:
    any of them
}