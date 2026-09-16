rule TTP_XOR_QUAD_CurrentVersionRun_714f {
  strings:
    $key_714f = { 22 20 [2] 06 2e [2] 2d 02 [2] 03 20 [2] 17 3b [2] 18 21 [2] 06 3c [2] 04 3d [2] 1f 3b [2] 03 3c [2] 1f 13 }

  condition:
    any of them
}