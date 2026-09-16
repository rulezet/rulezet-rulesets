rule TTP_XOR_QUAD_CurrentVersionRun_6e53 {
  strings:
    $key_6e53 = { 3d 3c [2] 19 32 [2] 32 1e [2] 1c 3c [2] 08 27 [2] 07 3d [2] 19 20 [2] 1b 21 [2] 00 27 [2] 1c 20 [2] 00 0f }

  condition:
    any of them
}