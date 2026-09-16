rule TTP_XOR_QUAD_CurrentVersionRun_6fb1 {
  strings:
    $key_6fb1 = { 3c de [2] 18 d0 [2] 33 fc [2] 1d de [2] 09 c5 [2] 06 df [2] 18 c2 [2] 1a c3 [2] 01 c5 [2] 1d c2 [2] 01 ed }

  condition:
    any of them
}