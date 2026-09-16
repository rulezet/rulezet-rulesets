rule TTP_XOR_QUAD_CurrentVersionRun_1eb1 {
  strings:
    $key_1eb1 = { 4d de [2] 69 d0 [2] 42 fc [2] 6c de [2] 78 c5 [2] 77 df [2] 69 c2 [2] 6b c3 [2] 70 c5 [2] 6c c2 [2] 70 ed }

  condition:
    any of them
}