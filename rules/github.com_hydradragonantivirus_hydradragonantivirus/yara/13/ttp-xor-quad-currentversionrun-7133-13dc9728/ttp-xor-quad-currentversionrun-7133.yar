rule TTP_XOR_QUAD_CurrentVersionRun_7133 {
  strings:
    $key_7133 = { 22 5c [2] 06 52 [2] 2d 7e [2] 03 5c [2] 17 47 [2] 18 5d [2] 06 40 [2] 04 41 [2] 1f 47 [2] 03 40 [2] 1f 6f }

  condition:
    any of them
}