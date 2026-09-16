rule TTP_XOR_QUAD_CurrentVersionRun_5302 {
  strings:
    $key_5302 = { 00 6d [2] 24 63 [2] 0f 4f [2] 21 6d [2] 35 76 [2] 3a 6c [2] 24 71 [2] 26 70 [2] 3d 76 [2] 21 71 [2] 3d 5e }

  condition:
    any of them
}