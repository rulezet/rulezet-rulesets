rule TTP_XOR_QUAD_CurrentVersionRun_2352 {
  strings:
    $key_2352 = { 70 3d [2] 54 33 [2] 7f 1f [2] 51 3d [2] 45 26 [2] 4a 3c [2] 54 21 [2] 56 20 [2] 4d 26 [2] 51 21 [2] 4d 0e }

  condition:
    any of them
}