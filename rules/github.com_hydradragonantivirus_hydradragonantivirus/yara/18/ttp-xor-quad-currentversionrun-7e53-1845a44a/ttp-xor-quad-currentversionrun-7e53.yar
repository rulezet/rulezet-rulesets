rule TTP_XOR_QUAD_CurrentVersionRun_7e53 {
  strings:
    $key_7e53 = { 2d 3c [2] 09 32 [2] 22 1e [2] 0c 3c [2] 18 27 [2] 17 3d [2] 09 20 [2] 0b 21 [2] 10 27 [2] 0c 20 [2] 10 0f }

  condition:
    any of them
}