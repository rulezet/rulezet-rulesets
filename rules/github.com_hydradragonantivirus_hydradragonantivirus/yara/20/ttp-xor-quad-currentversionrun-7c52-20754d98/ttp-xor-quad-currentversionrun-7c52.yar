rule TTP_XOR_QUAD_CurrentVersionRun_7c52 {
  strings:
    $key_7c52 = { 2f 3d [2] 0b 33 [2] 20 1f [2] 0e 3d [2] 1a 26 [2] 15 3c [2] 0b 21 [2] 09 20 [2] 12 26 [2] 0e 21 [2] 12 0e }

  condition:
    any of them
}