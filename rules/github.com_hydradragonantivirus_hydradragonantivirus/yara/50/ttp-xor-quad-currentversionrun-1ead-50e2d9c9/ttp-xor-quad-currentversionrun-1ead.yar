rule TTP_XOR_QUAD_CurrentVersionRun_1ead {
  strings:
    $key_1ead = { 4d c2 [2] 69 cc [2] 42 e0 [2] 6c c2 [2] 78 d9 [2] 77 c3 [2] 69 de [2] 6b df [2] 70 d9 [2] 6c de [2] 70 f1 }

  condition:
    any of them
}