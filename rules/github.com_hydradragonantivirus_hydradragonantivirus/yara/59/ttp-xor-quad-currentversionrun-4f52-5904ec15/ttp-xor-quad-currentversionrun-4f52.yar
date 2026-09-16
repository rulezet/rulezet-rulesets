rule TTP_XOR_QUAD_CurrentVersionRun_4f52 {
  strings:
    $key_4f52 = { 1c 3d [2] 38 33 [2] 13 1f [2] 3d 3d [2] 29 26 [2] 26 3c [2] 38 21 [2] 3a 20 [2] 21 26 [2] 3d 21 [2] 21 0e }

  condition:
    any of them
}