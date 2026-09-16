rule TTP_XOR_QUAD_CurrentVersionRun_1ab1 {
  strings:
    $key_1ab1 = { 49 de [2] 6d d0 [2] 46 fc [2] 68 de [2] 7c c5 [2] 73 df [2] 6d c2 [2] 6f c3 [2] 74 c5 [2] 68 c2 [2] 74 ed }

  condition:
    any of them
}