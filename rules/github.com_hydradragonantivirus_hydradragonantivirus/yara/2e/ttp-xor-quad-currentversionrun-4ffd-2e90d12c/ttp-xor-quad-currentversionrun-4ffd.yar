rule TTP_XOR_QUAD_CurrentVersionRun_4ffd {
  strings:
    $key_4ffd = { 1c 92 [2] 38 9c [2] 13 b0 [2] 3d 92 [2] 29 89 [2] 26 93 [2] 38 8e [2] 3a 8f [2] 21 89 [2] 3d 8e [2] 21 a1 }

  condition:
    any of them
}