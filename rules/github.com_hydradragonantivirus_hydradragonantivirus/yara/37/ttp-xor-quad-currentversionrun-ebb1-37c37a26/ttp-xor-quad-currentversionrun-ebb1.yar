rule TTP_XOR_QUAD_CurrentVersionRun_ebb1 {
  strings:
    $key_ebb1 = { b8 de [2] 9c d0 [2] b7 fc [2] 99 de [2] 8d c5 [2] 82 df [2] 9c c2 [2] 9e c3 [2] 85 c5 [2] 99 c2 [2] 85 ed }

  condition:
    any of them
}