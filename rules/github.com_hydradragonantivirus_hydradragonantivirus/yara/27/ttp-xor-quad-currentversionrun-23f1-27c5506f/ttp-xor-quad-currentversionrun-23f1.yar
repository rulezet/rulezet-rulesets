rule TTP_XOR_QUAD_CurrentVersionRun_23f1 {
  strings:
    $key_23f1 = { 70 9e [2] 54 90 [2] 7f bc [2] 51 9e [2] 45 85 [2] 4a 9f [2] 54 82 [2] 56 83 [2] 4d 85 [2] 51 82 [2] 4d ad }

  condition:
    any of them
}