rule TTP_XOR_QUAD_CurrentVersionRun_7f53 {
  strings:
    $key_7f53 = { 2c 3c [2] 08 32 [2] 23 1e [2] 0d 3c [2] 19 27 [2] 16 3d [2] 08 20 [2] 0a 21 [2] 11 27 [2] 0d 20 [2] 11 0f }

  condition:
    any of them
}