rule TTP_XOR_QUAD_CurrentVersionRun_2aac {
  strings:
    $key_2aac = { 79 c3 [2] 5d cd [2] 76 e1 [2] 58 c3 [2] 4c d8 [2] 43 c2 [2] 5d df [2] 5f de [2] 44 d8 [2] 58 df [2] 44 f0 }

  condition:
    any of them
}