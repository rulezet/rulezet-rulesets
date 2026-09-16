rule TTP_XOR_QUAD_CurrentVersionRun_03b1 {
  strings:
    $key_03b1 = { 50 de [2] 74 d0 [2] 5f fc [2] 71 de [2] 65 c5 [2] 6a df [2] 74 c2 [2] 76 c3 [2] 6d c5 [2] 71 c2 [2] 6d ed }

  condition:
    any of them
}