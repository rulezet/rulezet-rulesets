rule TTP_XOR_QUAD_CurrentVersionRun_7052 {
  strings:
    $key_7052 = { 23 3d [2] 07 33 [2] 2c 1f [2] 02 3d [2] 16 26 [2] 19 3c [2] 07 21 [2] 05 20 [2] 1e 26 [2] 02 21 [2] 1e 0e }

  condition:
    any of them
}