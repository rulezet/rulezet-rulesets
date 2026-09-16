rule TTP_XOR_QUAD_CurrentVersionRun_7852 {
  strings:
    $key_7852 = { 2b 3d [2] 0f 33 [2] 24 1f [2] 0a 3d [2] 1e 26 [2] 11 3c [2] 0f 21 [2] 0d 20 [2] 16 26 [2] 0a 21 [2] 16 0e }

  condition:
    any of them
}