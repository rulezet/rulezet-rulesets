rule TTP_XOR_QUAD_CurrentVersionRun_3152 {
  strings:
    $key_3152 = { 62 3d [2] 46 33 [2] 6d 1f [2] 43 3d [2] 57 26 [2] 58 3c [2] 46 21 [2] 44 20 [2] 5f 26 [2] 43 21 [2] 5f 0e }

  condition:
    any of them
}