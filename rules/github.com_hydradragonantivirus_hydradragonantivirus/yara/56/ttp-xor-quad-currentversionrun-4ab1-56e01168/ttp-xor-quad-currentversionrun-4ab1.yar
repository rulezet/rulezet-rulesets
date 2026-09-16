rule TTP_XOR_QUAD_CurrentVersionRun_4ab1 {
  strings:
    $key_4ab1 = { 19 de [2] 3d d0 [2] 16 fc [2] 38 de [2] 2c c5 [2] 23 df [2] 3d c2 [2] 3f c3 [2] 24 c5 [2] 38 c2 [2] 24 ed }

  condition:
    any of them
}