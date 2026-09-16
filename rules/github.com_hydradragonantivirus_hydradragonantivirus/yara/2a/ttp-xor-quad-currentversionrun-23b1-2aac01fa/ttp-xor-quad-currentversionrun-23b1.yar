rule TTP_XOR_QUAD_CurrentVersionRun_23b1 {
  strings:
    $key_23b1 = { 70 de [2] 54 d0 [2] 7f fc [2] 51 de [2] 45 c5 [2] 4a df [2] 54 c2 [2] 56 c3 [2] 4d c5 [2] 51 c2 [2] 4d ed }

  condition:
    any of them
}