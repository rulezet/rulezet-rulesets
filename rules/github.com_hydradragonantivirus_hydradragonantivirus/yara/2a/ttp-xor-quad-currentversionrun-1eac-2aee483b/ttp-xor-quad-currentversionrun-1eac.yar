rule TTP_XOR_QUAD_CurrentVersionRun_1eac {
  strings:
    $key_1eac = { 4d c3 [2] 69 cd [2] 42 e1 [2] 6c c3 [2] 78 d8 [2] 77 c2 [2] 69 df [2] 6b de [2] 70 d8 [2] 6c df [2] 70 f0 }

  condition:
    any of them
}