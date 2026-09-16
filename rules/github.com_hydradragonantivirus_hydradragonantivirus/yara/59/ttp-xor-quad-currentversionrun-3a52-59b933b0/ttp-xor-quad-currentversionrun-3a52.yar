rule TTP_XOR_QUAD_CurrentVersionRun_3a52 {
  strings:
    $key_3a52 = { 69 3d [2] 4d 33 [2] 66 1f [2] 48 3d [2] 5c 26 [2] 53 3c [2] 4d 21 [2] 4f 20 [2] 54 26 [2] 48 21 [2] 54 0e }

  condition:
    any of them
}