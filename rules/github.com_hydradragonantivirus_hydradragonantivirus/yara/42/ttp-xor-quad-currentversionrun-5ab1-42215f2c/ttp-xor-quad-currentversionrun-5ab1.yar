rule TTP_XOR_QUAD_CurrentVersionRun_5ab1 {
  strings:
    $key_5ab1 = { 09 de [2] 2d d0 [2] 06 fc [2] 28 de [2] 3c c5 [2] 33 df [2] 2d c2 [2] 2f c3 [2] 34 c5 [2] 28 c2 [2] 34 ed }

  condition:
    any of them
}