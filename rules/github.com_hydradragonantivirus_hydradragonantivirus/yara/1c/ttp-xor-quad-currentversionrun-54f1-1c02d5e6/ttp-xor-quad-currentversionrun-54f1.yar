rule TTP_XOR_QUAD_CurrentVersionRun_54f1 {
  strings:
    $key_54f1 = { 07 9e [2] 23 90 [2] 08 bc [2] 26 9e [2] 32 85 [2] 3d 9f [2] 23 82 [2] 21 83 [2] 3a 85 [2] 26 82 [2] 3a ad }

  condition:
    any of them
}