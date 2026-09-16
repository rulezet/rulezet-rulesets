rule TTP_XOR_QUAD_CurrentVersionRun_4a03 {
  strings:
    $key_4a03 = { 19 6c [2] 3d 62 [2] 16 4e [2] 38 6c [2] 2c 77 [2] 23 6d [2] 3d 70 [2] 3f 71 [2] 24 77 [2] 38 70 [2] 24 5f }

  condition:
    any of them
}