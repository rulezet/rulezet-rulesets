rule TTP_XOR_QUAD_CurrentVersionRun_5452 {
  strings:
    $key_5452 = { 07 3d [2] 23 33 [2] 08 1f [2] 26 3d [2] 32 26 [2] 3d 3c [2] 23 21 [2] 21 20 [2] 3a 26 [2] 26 21 [2] 3a 0e }

  condition:
    any of them
}