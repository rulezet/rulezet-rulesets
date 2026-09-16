rule TTP_XOR_QUAD_CurrentVersionRun_5eb1 {
  strings:
    $key_5eb1 = { 0d de [2] 29 d0 [2] 02 fc [2] 2c de [2] 38 c5 [2] 37 df [2] 29 c2 [2] 2b c3 [2] 30 c5 [2] 2c c2 [2] 30 ed }

  condition:
    any of them
}