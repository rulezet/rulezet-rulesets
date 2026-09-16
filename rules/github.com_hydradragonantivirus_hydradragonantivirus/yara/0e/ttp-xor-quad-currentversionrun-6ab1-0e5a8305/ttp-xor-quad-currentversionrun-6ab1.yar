rule TTP_XOR_QUAD_CurrentVersionRun_6ab1 {
  strings:
    $key_6ab1 = { 39 de [2] 1d d0 [2] 36 fc [2] 18 de [2] 0c c5 [2] 03 df [2] 1d c2 [2] 1f c3 [2] 04 c5 [2] 18 c2 [2] 04 ed }

  condition:
    any of them
}