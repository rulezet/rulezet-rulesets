rule TTP_XOR_QUAD_CurrentVersionRun_7ab1 {
  strings:
    $key_7ab1 = { 29 de [2] 0d d0 [2] 26 fc [2] 08 de [2] 1c c5 [2] 13 df [2] 0d c2 [2] 0f c3 [2] 14 c5 [2] 08 c2 [2] 14 ed }

  condition:
    any of them
}