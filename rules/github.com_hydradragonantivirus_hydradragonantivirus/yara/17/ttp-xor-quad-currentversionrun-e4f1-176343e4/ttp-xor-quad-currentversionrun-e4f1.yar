rule TTP_XOR_QUAD_CurrentVersionRun_e4f1 {
  strings:
    $key_e4f1 = { b7 9e [2] 93 90 [2] b8 bc [2] 96 9e [2] 82 85 [2] 8d 9f [2] 93 82 [2] 91 83 [2] 8a 85 [2] 96 82 [2] 8a ad }

  condition:
    any of them
}