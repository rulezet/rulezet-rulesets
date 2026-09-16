rule TTP_XOR_QUAD_CurrentVersionRun_4852 {
  strings:
    $key_4852 = { 1b 3d [2] 3f 33 [2] 14 1f [2] 3a 3d [2] 2e 26 [2] 21 3c [2] 3f 21 [2] 3d 20 [2] 26 26 [2] 3a 21 [2] 26 0e }

  condition:
    any of them
}