rule TTP_XOR_QUAD_CurrentVersionRun_7bb1 {
  strings:
    $key_7bb1 = { 28 de [2] 0c d0 [2] 27 fc [2] 09 de [2] 1d c5 [2] 12 df [2] 0c c2 [2] 0e c3 [2] 15 c5 [2] 09 c2 [2] 15 ed }

  condition:
    any of them
}