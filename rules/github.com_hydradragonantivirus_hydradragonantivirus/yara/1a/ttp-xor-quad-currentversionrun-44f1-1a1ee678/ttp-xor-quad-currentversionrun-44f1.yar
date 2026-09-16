rule TTP_XOR_QUAD_CurrentVersionRun_44f1 {
  strings:
    $key_44f1 = { 17 9e [2] 33 90 [2] 18 bc [2] 36 9e [2] 22 85 [2] 2d 9f [2] 33 82 [2] 31 83 [2] 2a 85 [2] 36 82 [2] 2a ad }

  condition:
    any of them
}