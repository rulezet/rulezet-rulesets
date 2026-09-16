rule TTP_XOR_QUAD_CurrentVersionRun_04b1 {
  strings:
    $key_04b1 = { 57 de [2] 73 d0 [2] 58 fc [2] 76 de [2] 62 c5 [2] 6d df [2] 73 c2 [2] 71 c3 [2] 6a c5 [2] 76 c2 [2] 6a ed }

  condition:
    any of them
}