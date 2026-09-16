rule TTP_XOR_QUAD_CurrentVersionRun_04f1 {
  strings:
    $key_04f1 = { 57 9e [2] 73 90 [2] 58 bc [2] 76 9e [2] 62 85 [2] 6d 9f [2] 73 82 [2] 71 83 [2] 6a 85 [2] 76 82 [2] 6a ad }

  condition:
    any of them
}