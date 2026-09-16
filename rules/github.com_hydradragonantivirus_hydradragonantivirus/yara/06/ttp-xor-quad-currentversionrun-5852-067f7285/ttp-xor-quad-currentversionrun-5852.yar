rule TTP_XOR_QUAD_CurrentVersionRun_5852 {
  strings:
    $key_5852 = { 0b 3d [2] 2f 33 [2] 04 1f [2] 2a 3d [2] 3e 26 [2] 31 3c [2] 2f 21 [2] 2d 20 [2] 36 26 [2] 2a 21 [2] 36 0e }

  condition:
    any of them
}