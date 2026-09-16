rule TTP_XOR_QUAD_CurrentVersionRun_4833 {
  strings:
    $key_4833 = { 1b 5c [2] 3f 52 [2] 14 7e [2] 3a 5c [2] 2e 47 [2] 21 5d [2] 3f 40 [2] 3d 41 [2] 26 47 [2] 3a 40 [2] 26 6f }

  condition:
    any of them
}