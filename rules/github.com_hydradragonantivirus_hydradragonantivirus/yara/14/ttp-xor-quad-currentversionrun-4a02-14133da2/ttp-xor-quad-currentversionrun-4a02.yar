rule TTP_XOR_QUAD_CurrentVersionRun_4a02 {
  strings:
    $key_4a02 = { 19 6d [2] 3d 63 [2] 16 4f [2] 38 6d [2] 2c 76 [2] 23 6c [2] 3d 71 [2] 3f 70 [2] 24 76 [2] 38 71 [2] 24 5e }

  condition:
    any of them
}