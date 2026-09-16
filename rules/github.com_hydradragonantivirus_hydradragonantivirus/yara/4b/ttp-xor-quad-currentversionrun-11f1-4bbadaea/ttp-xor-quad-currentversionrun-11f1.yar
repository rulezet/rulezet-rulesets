rule TTP_XOR_QUAD_CurrentVersionRun_11f1 {
  strings:
    $key_11f1 = { 42 9e [2] 66 90 [2] 4d bc [2] 63 9e [2] 77 85 [2] 78 9f [2] 66 82 [2] 64 83 [2] 7f 85 [2] 63 82 [2] 7f ad }

  condition:
    any of them
}