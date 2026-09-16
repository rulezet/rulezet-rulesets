rule TTP_XOR_QUAD_CurrentVersionRun_1fb1 {
  strings:
    $key_1fb1 = { 4c de [2] 68 d0 [2] 43 fc [2] 6d de [2] 79 c5 [2] 76 df [2] 68 c2 [2] 6a c3 [2] 71 c5 [2] 6d c2 [2] 71 ed }

  condition:
    any of them
}