rule TTP_XOR_QUAD_CurrentVersionRun_4c52 {
  strings:
    $key_4c52 = { 1f 3d [2] 3b 33 [2] 10 1f [2] 3e 3d [2] 2a 26 [2] 25 3c [2] 3b 21 [2] 39 20 [2] 22 26 [2] 3e 21 [2] 22 0e }

  condition:
    any of them
}