rule TTP_XOR_QUAD_CurrentVersionRun_25b1 {
  strings:
    $key_25b1 = { 76 de [2] 52 d0 [2] 79 fc [2] 57 de [2] 43 c5 [2] 4c df [2] 52 c2 [2] 50 c3 [2] 4b c5 [2] 57 c2 [2] 4b ed }

  condition:
    any of them
}