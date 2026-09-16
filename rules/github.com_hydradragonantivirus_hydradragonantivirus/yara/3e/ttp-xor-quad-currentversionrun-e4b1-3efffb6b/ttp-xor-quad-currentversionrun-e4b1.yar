rule TTP_XOR_QUAD_CurrentVersionRun_e4b1 {
  strings:
    $key_e4b1 = { b7 de [2] 93 d0 [2] b8 fc [2] 96 de [2] 82 c5 [2] 8d df [2] 93 c2 [2] 91 c3 [2] 8a c5 [2] 96 c2 [2] 8a ed }

  condition:
    any of them
}