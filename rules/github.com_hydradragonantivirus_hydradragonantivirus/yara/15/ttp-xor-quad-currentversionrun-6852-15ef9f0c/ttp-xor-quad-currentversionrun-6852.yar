rule TTP_XOR_QUAD_CurrentVersionRun_6852 {
  strings:
    $key_6852 = { 3b 3d [2] 1f 33 [2] 34 1f [2] 1a 3d [2] 0e 26 [2] 01 3c [2] 1f 21 [2] 1d 20 [2] 06 26 [2] 1a 21 [2] 06 0e }

  condition:
    any of them
}