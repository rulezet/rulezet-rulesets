rule TTP_XOR_QUAD_CurrentVersionRun_4f51 {
  strings:
    $key_4f51 = { 1c 3e [2] 38 30 [2] 13 1c [2] 3d 3e [2] 29 25 [2] 26 3f [2] 38 22 [2] 3a 23 [2] 21 25 [2] 3d 22 [2] 21 0d }

  condition:
    any of them
}