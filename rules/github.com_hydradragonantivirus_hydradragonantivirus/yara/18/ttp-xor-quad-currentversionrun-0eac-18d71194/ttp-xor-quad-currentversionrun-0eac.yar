rule TTP_XOR_QUAD_CurrentVersionRun_0eac {
  strings:
    $key_0eac = { 5d c3 [2] 79 cd [2] 52 e1 [2] 7c c3 [2] 68 d8 [2] 67 c2 [2] 79 df [2] 7b de [2] 60 d8 [2] 7c df [2] 60 f0 }

  condition:
    any of them
}