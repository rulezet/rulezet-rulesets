rule TTP_XOR_QUAD_CurrentVersionRun_6653 {
  strings:
    $key_6653 = { 35 3c [2] 11 32 [2] 3a 1e [2] 14 3c [2] 00 27 [2] 0f 3d [2] 11 20 [2] 13 21 [2] 08 27 [2] 14 20 [2] 08 0f }

  condition:
    any of them
}