rule TTP_XOR_QUAD_CurrentVersionRun_15ac {
  strings:
    $key_15ac = { 46 c3 [2] 62 cd [2] 49 e1 [2] 67 c3 [2] 73 d8 [2] 7c c2 [2] 62 df [2] 60 de [2] 7b d8 [2] 67 df [2] 7b f0 }

  condition:
    any of them
}