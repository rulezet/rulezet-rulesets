rule TTP_XOR_QUAD_CurrentVersionRun_53ef {
  strings:
    $key_53ef = { 00 80 [2] 24 8e [2] 0f a2 [2] 21 80 [2] 35 9b [2] 3a 81 [2] 24 9c [2] 26 9d [2] 3d 9b [2] 21 9c [2] 3d b3 }

  condition:
    any of them
}