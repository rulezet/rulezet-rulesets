rule TTP_XOR_QUAD_CurrentVersionRun_53f1 {
  strings:
    $key_53f1 = { 00 9e [2] 24 90 [2] 0f bc [2] 21 9e [2] 35 85 [2] 3a 9f [2] 24 82 [2] 26 83 [2] 3d 85 [2] 21 82 [2] 3d ad }

  condition:
    any of them
}