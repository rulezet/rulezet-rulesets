rule TTP_XOR_QUAD_CurrentVersionRun_4f33 {
  strings:
    $key_4f33 = { 1c 5c [2] 38 52 [2] 13 7e [2] 3d 5c [2] 29 47 [2] 26 5d [2] 38 40 [2] 3a 41 [2] 21 47 [2] 3d 40 [2] 21 6f }

  condition:
    any of them
}