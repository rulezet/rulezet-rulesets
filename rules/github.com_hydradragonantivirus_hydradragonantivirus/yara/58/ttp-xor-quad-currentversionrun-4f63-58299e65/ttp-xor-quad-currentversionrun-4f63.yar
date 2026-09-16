rule TTP_XOR_QUAD_CurrentVersionRun_4f63 {
  strings:
    $key_4f63 = { 1c 0c [2] 38 02 [2] 13 2e [2] 3d 0c [2] 29 17 [2] 26 0d [2] 38 10 [2] 3a 11 [2] 21 17 [2] 3d 10 [2] 21 3f }

  condition:
    any of them
}