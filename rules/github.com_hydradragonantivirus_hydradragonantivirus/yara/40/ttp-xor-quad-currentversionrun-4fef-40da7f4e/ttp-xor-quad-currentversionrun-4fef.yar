rule TTP_XOR_QUAD_CurrentVersionRun_4fef {
  strings:
    $key_4fef = { 1c 80 [2] 38 8e [2] 13 a2 [2] 3d 80 [2] 29 9b [2] 26 81 [2] 38 9c [2] 3a 9d [2] 21 9b [2] 3d 9c [2] 21 b3 }

  condition:
    any of them
}