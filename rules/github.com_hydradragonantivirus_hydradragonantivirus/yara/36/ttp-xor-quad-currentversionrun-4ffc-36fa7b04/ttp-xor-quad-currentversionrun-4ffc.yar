rule TTP_XOR_QUAD_CurrentVersionRun_4ffc {
  strings:
    $key_4ffc = { 1c 93 [2] 38 9d [2] 13 b1 [2] 3d 93 [2] 29 88 [2] 26 92 [2] 38 8f [2] 3a 8e [2] 21 88 [2] 3d 8f [2] 21 a0 }

  condition:
    any of them
}