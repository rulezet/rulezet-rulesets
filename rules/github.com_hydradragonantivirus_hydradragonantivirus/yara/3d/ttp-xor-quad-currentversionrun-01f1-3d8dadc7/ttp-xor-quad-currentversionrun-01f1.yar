rule TTP_XOR_QUAD_CurrentVersionRun_01f1 {
  strings:
    $key_01f1 = { 52 9e [2] 76 90 [2] 5d bc [2] 73 9e [2] 67 85 [2] 68 9f [2] 76 82 [2] 74 83 [2] 6f 85 [2] 73 82 [2] 6f ad }

  condition:
    any of them
}