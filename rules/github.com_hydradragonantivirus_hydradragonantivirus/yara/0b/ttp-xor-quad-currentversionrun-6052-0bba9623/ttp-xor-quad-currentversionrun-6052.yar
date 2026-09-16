rule TTP_XOR_QUAD_CurrentVersionRun_6052 {
  strings:
    $key_6052 = { 33 3d [2] 17 33 [2] 3c 1f [2] 12 3d [2] 06 26 [2] 09 3c [2] 17 21 [2] 15 20 [2] 0e 26 [2] 12 21 [2] 0e 0e }

  condition:
    any of them
}