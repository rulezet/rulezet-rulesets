rule TTP_XOR_QUAD_CurrentVersionRun_33f1 {
  strings:
    $key_33f1 = { 60 9e [2] 44 90 [2] 6f bc [2] 41 9e [2] 55 85 [2] 5a 9f [2] 44 82 [2] 46 83 [2] 5d 85 [2] 41 82 [2] 5d ad }

  condition:
    any of them
}