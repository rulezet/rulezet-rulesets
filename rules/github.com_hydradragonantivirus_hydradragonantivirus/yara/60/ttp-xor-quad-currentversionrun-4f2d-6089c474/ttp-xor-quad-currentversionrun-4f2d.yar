rule TTP_XOR_QUAD_CurrentVersionRun_4f2d {
  strings:
    $key_4f2d = { 1c 42 [2] 38 4c [2] 13 60 [2] 3d 42 [2] 29 59 [2] 26 43 [2] 38 5e [2] 3a 5f [2] 21 59 [2] 3d 5e [2] 21 71 }

  condition:
    any of them
}