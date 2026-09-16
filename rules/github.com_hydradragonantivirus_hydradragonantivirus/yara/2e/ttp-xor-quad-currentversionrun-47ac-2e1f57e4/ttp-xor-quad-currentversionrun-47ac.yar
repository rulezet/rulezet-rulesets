rule TTP_XOR_QUAD_CurrentVersionRun_47ac {
  strings:
    $key_47ac = { 14 c3 [2] 30 cd [2] 1b e1 [2] 35 c3 [2] 21 d8 [2] 2e c2 [2] 30 df [2] 32 de [2] 29 d8 [2] 35 df [2] 29 f0 }

  condition:
    any of them
}