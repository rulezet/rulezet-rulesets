rule TTP_XOR_QUAD_CurrentVersionRun_4f62 {
  strings:
    $key_4f62 = { 1c 0d [2] 38 03 [2] 13 2f [2] 3d 0d [2] 29 16 [2] 26 0c [2] 38 11 [2] 3a 10 [2] 21 16 [2] 3d 11 [2] 21 3e }

  condition:
    any of them
}