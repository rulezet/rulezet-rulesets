rule TTP_XOR_QUAD_CurrentVersionRun_13b1 {
  strings:
    $key_13b1 = { 40 de [2] 64 d0 [2] 4f fc [2] 61 de [2] 75 c5 [2] 7a df [2] 64 c2 [2] 66 c3 [2] 7d c5 [2] 61 c2 [2] 7d ed }

  condition:
    any of them
}