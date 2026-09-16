rule TTP_XOR_QUAD_CurrentVersionRun_21f1 {
  strings:
    $key_21f1 = { 72 9e [2] 56 90 [2] 7d bc [2] 53 9e [2] 47 85 [2] 48 9f [2] 56 82 [2] 54 83 [2] 4f 85 [2] 53 82 [2] 4f ad }

  condition:
    any of them
}