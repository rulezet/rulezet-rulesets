rule TTP_XOR_QUAD_CurrentVersionRun_4f1d {
  strings:
    $key_4f1d = { 1c 72 [2] 38 7c [2] 13 50 [2] 3d 72 [2] 29 69 [2] 26 73 [2] 38 6e [2] 3a 6f [2] 21 69 [2] 3d 6e [2] 21 41 }

  condition:
    any of them
}