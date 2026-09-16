rule TTP_XOR_QUAD_CurrentVersionRun_52b1 {
  strings:
    $key_52b1 = { 01 de [2] 25 d0 [2] 0e fc [2] 20 de [2] 34 c5 [2] 3b df [2] 25 c2 [2] 27 c3 [2] 3c c5 [2] 20 c2 [2] 3c ed }

  condition:
    any of them
}