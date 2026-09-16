rule TTP_XOR_QUAD_CurrentVersionRun_0bac {
  strings:
    $key_0bac = { 58 c3 [2] 7c cd [2] 57 e1 [2] 79 c3 [2] 6d d8 [2] 62 c2 [2] 7c df [2] 7e de [2] 65 d8 [2] 79 df [2] 65 f0 }

  condition:
    any of them
}