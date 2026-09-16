rule TTP_XOR_QUAD_CurrentVersionRun_6952 {
  strings:
    $key_6952 = { 3a 3d [2] 1e 33 [2] 35 1f [2] 1b 3d [2] 0f 26 [2] 00 3c [2] 1e 21 [2] 1c 20 [2] 07 26 [2] 1b 21 [2] 07 0e }

  condition:
    any of them
}