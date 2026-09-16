rule TTP_XOR_QUAD_CurrentVersionRun_48ef {
  strings:
    $key_48ef = { 1b 80 [2] 3f 8e [2] 14 a2 [2] 3a 80 [2] 2e 9b [2] 21 81 [2] 3f 9c [2] 3d 9d [2] 26 9b [2] 3a 9c [2] 26 b3 }

  condition:
    any of them
}