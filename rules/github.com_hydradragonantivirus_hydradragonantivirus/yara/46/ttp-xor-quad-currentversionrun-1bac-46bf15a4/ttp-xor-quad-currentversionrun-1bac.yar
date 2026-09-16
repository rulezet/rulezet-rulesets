rule TTP_XOR_QUAD_CurrentVersionRun_1bac {
  strings:
    $key_1bac = { 48 c3 [2] 6c cd [2] 47 e1 [2] 69 c3 [2] 7d d8 [2] 72 c2 [2] 6c df [2] 6e de [2] 75 d8 [2] 69 df [2] 75 f0 }

  condition:
    any of them
}