rule TTP_XOR_QUAD_CurrentVersionRun_51f1 {
  strings:
    $key_51f1 = { 02 9e [2] 26 90 [2] 0d bc [2] 23 9e [2] 37 85 [2] 38 9f [2] 26 82 [2] 24 83 [2] 3f 85 [2] 23 82 [2] 3f ad }

  condition:
    any of them
}