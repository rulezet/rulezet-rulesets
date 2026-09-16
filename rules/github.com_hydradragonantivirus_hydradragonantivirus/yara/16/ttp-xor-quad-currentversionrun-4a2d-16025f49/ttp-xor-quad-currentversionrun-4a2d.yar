rule TTP_XOR_QUAD_CurrentVersionRun_4a2d {
  strings:
    $key_4a2d = { 19 42 [2] 3d 4c [2] 16 60 [2] 38 42 [2] 2c 59 [2] 23 43 [2] 3d 5e [2] 3f 5f [2] 24 59 [2] 38 5e [2] 24 71 }

  condition:
    any of them
}