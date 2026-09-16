rule TTP_XOR_QUAD_CurrentVersionRun_4aed {
  strings:
    $key_4aed = { 19 82 [2] 3d 8c [2] 16 a0 [2] 38 82 [2] 2c 99 [2] 23 83 [2] 3d 9e [2] 3f 9f [2] 24 99 [2] 38 9e [2] 24 b1 }

  condition:
    any of them
}