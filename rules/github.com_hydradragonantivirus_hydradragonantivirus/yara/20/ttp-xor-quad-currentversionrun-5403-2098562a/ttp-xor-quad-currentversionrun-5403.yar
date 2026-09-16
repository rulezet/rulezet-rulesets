rule TTP_XOR_QUAD_CurrentVersionRun_5403 {
  strings:
    $key_5403 = { 07 6c [2] 23 62 [2] 08 4e [2] 26 6c [2] 32 77 [2] 3d 6d [2] 23 70 [2] 21 71 [2] 3a 77 [2] 26 70 [2] 3a 5f }

  condition:
    any of them
}