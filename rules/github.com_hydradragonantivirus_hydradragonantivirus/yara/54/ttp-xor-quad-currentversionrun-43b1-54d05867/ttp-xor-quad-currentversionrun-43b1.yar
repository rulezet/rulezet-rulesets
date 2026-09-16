rule TTP_XOR_QUAD_CurrentVersionRun_43b1 {
  strings:
    $key_43b1 = { 10 de [2] 34 d0 [2] 1f fc [2] 31 de [2] 25 c5 [2] 2a df [2] 34 c2 [2] 36 c3 [2] 2d c5 [2] 31 c2 [2] 2d ed }

  condition:
    any of them
}