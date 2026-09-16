rule TTP_XOR_QUAD_CurrentVersionRun_fbb1 {
  strings:
    $key_fbb1 = { a8 de [2] 8c d0 [2] a7 fc [2] 89 de [2] 9d c5 [2] 92 df [2] 8c c2 [2] 8e c3 [2] 95 c5 [2] 89 c2 [2] 95 ed }

  condition:
    any of them
}