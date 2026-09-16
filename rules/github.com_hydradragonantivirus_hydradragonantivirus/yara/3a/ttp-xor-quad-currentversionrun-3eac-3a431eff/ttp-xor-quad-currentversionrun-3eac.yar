rule TTP_XOR_QUAD_CurrentVersionRun_3eac {
  strings:
    $key_3eac = { 6d c3 [2] 49 cd [2] 62 e1 [2] 4c c3 [2] 58 d8 [2] 57 c2 [2] 49 df [2] 4b de [2] 50 d8 [2] 4c df [2] 50 f0 }

  condition:
    any of them
}