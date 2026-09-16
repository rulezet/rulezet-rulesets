rule TTP_XOR_QUAD_CurrentVersionRun_7952 {
  strings:
    $key_7952 = { 2a 3d [2] 0e 33 [2] 25 1f [2] 0b 3d [2] 1f 26 [2] 10 3c [2] 0e 21 [2] 0c 20 [2] 17 26 [2] 0b 21 [2] 17 0e }

  condition:
    any of them
}