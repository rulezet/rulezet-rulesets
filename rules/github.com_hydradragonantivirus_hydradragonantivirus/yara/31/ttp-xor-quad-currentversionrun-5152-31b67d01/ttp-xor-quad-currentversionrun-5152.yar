rule TTP_XOR_QUAD_CurrentVersionRun_5152 {
  strings:
    $key_5152 = { 02 3d [2] 26 33 [2] 0d 1f [2] 23 3d [2] 37 26 [2] 38 3c [2] 26 21 [2] 24 20 [2] 3f 26 [2] 23 21 [2] 3f 0e }

  condition:
    any of them
}