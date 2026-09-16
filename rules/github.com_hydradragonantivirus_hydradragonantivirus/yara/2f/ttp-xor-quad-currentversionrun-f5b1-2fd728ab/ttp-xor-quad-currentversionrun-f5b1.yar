rule TTP_XOR_QUAD_CurrentVersionRun_f5b1 {
  strings:
    $key_f5b1 = { a6 de [2] 82 d0 [2] a9 fc [2] 87 de [2] 93 c5 [2] 9c df [2] 82 c2 [2] 80 c3 [2] 9b c5 [2] 87 c2 [2] 9b ed }

  condition:
    any of them
}