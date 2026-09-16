rule TTP_XOR_QUAD_CurrentVersionRun_44ef {
  strings:
    $key_44ef = { 17 80 [2] 33 8e [2] 18 a2 [2] 36 80 [2] 22 9b [2] 2d 81 [2] 33 9c [2] 31 9d [2] 2a 9b [2] 36 9c [2] 2a b3 }

  condition:
    any of them
}