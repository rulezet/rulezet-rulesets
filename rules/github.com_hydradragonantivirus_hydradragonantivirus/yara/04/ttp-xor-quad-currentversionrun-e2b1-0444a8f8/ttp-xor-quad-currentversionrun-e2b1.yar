rule TTP_XOR_QUAD_CurrentVersionRun_e2b1 {
  strings:
    $key_e2b1 = { b1 de [2] 95 d0 [2] be fc [2] 90 de [2] 84 c5 [2] 8b df [2] 95 c2 [2] 97 c3 [2] 8c c5 [2] 90 c2 [2] 8c ed }

  condition:
    any of them
}