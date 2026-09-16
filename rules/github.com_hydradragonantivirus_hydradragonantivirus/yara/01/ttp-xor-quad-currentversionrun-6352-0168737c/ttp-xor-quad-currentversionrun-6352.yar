rule TTP_XOR_QUAD_CurrentVersionRun_6352 {
  strings:
    $key_6352 = { 30 3d [2] 14 33 [2] 3f 1f [2] 11 3d [2] 05 26 [2] 0a 3c [2] 14 21 [2] 16 20 [2] 0d 26 [2] 11 21 [2] 0d 0e }

  condition:
    any of them
}