rule TTP_XOR_QUAD_CurrentVersionRun_f9ad {
  strings:
    $key_f9ad = { aa c2 [2] 8e cc [2] a5 e0 [2] 8b c2 [2] 9f d9 [2] 90 c3 [2] 8e de [2] 8c df [2] 97 d9 [2] 8b de [2] 97 f1 }

  condition:
    any of them
}