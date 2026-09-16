rule TTP_XOR_QUAD_CurrentVersionRun_4a23 {
  strings:
    $key_4a23 = { 19 4c [2] 3d 42 [2] 16 6e [2] 38 4c [2] 2c 57 [2] 23 4d [2] 3d 50 [2] 3f 51 [2] 24 57 [2] 38 50 [2] 24 7f }

  condition:
    any of them
}