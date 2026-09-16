rule TTP_XOR_QUAD_CurrentVersionRun_5d52 {
  strings:
    $key_5d52 = { 0e 3d [2] 2a 33 [2] 01 1f [2] 2f 3d [2] 3b 26 [2] 34 3c [2] 2a 21 [2] 28 20 [2] 33 26 [2] 2f 21 [2] 33 0e }

  condition:
    any of them
}