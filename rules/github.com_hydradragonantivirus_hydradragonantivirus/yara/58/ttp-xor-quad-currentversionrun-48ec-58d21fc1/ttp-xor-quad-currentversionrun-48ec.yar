rule TTP_XOR_QUAD_CurrentVersionRun_48ec {
  strings:
    $key_48ec = { 1b 83 [2] 3f 8d [2] 14 a1 [2] 3a 83 [2] 2e 98 [2] 21 82 [2] 3f 9f [2] 3d 9e [2] 26 98 [2] 3a 9f [2] 26 b0 }

  condition:
    any of them
}