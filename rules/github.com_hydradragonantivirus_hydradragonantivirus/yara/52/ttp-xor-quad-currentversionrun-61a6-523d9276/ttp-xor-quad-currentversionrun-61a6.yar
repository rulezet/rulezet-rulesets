rule TTP_XOR_QUAD_CurrentVersionRun_61a6 {
  strings:
    $key_61a6 = { 32 c9 [2] 16 c7 [2] 3d eb [2] 13 c9 [2] 07 d2 [2] 08 c8 [2] 16 d5 [2] 14 d4 [2] 0f d2 [2] 13 d5 [2] 0f fa }

  condition:
    any of them
}