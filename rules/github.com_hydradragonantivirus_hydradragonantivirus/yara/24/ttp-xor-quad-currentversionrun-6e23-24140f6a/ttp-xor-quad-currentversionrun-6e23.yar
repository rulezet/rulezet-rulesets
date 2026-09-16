rule TTP_XOR_QUAD_CurrentVersionRun_6e23 {
  strings:
    $key_6e23 = { 3d 4c [2] 19 42 [2] 32 6e [2] 1c 4c [2] 08 57 [2] 07 4d [2] 19 50 [2] 1b 51 [2] 00 57 [2] 1c 50 [2] 00 7f }

  condition:
    any of them
}