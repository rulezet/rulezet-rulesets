rule TTP_XOR_QUAD_CurrentVersionRun_2552 {
  strings:
    $key_2552 = { 76 3d [2] 52 33 [2] 79 1f [2] 57 3d [2] 43 26 [2] 4c 3c [2] 52 21 [2] 50 20 [2] 4b 26 [2] 57 21 [2] 4b 0e }

  condition:
    any of them
}