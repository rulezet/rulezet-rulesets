rule TTP_XOR_QUAD_CurrentVersionRun_4f71 {
  strings:
    $key_4f71 = { 1c 1e [2] 38 10 [2] 13 3c [2] 3d 1e [2] 29 05 [2] 26 1f [2] 38 02 [2] 3a 03 [2] 21 05 [2] 3d 02 [2] 21 2d }

  condition:
    any of them
}