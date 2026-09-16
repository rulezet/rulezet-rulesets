rule TTP_XOR_QUAD_CurrentVersionRun_2252 {
  strings:
    $key_2252 = { 71 3d [2] 55 33 [2] 7e 1f [2] 50 3d [2] 44 26 [2] 4b 3c [2] 55 21 [2] 57 20 [2] 4c 26 [2] 50 21 [2] 4c 0e }

  condition:
    any of them
}