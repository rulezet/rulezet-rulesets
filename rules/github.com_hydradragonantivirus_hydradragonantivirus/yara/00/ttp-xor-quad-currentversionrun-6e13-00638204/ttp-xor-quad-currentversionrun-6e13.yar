rule TTP_XOR_QUAD_CurrentVersionRun_6e13 {
  strings:
    $key_6e13 = { 3d 7c [2] 19 72 [2] 32 5e [2] 1c 7c [2] 08 67 [2] 07 7d [2] 19 60 [2] 1b 61 [2] 00 67 [2] 1c 60 [2] 00 4f }

  condition:
    any of them
}