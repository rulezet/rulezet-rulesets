rule TTP_XOR_QUAD_CurrentVersionRun_17ac {
  strings:
    $key_17ac = { 44 c3 [2] 60 cd [2] 4b e1 [2] 65 c3 [2] 71 d8 [2] 7e c2 [2] 60 df [2] 62 de [2] 79 d8 [2] 65 df [2] 79 f0 }

  condition:
    any of them
}