rule TTP_XOR_QUAD_CurrentVersionRun_14b1 {
  strings:
    $key_14b1 = { 47 de [2] 63 d0 [2] 48 fc [2] 66 de [2] 72 c5 [2] 7d df [2] 63 c2 [2] 61 c3 [2] 7a c5 [2] 66 c2 [2] 7a ed }

  condition:
    any of them
}