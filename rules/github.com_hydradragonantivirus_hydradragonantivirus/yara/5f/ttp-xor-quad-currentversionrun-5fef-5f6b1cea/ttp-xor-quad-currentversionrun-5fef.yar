rule TTP_XOR_QUAD_CurrentVersionRun_5fef {
  strings:
    $key_5fef = { 0c 80 [2] 28 8e [2] 03 a2 [2] 2d 80 [2] 39 9b [2] 36 81 [2] 28 9c [2] 2a 9d [2] 31 9b [2] 2d 9c [2] 31 b3 }

  condition:
    any of them
}