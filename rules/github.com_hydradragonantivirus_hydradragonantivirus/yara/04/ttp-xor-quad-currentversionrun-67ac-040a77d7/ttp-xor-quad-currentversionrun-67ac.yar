rule TTP_XOR_QUAD_CurrentVersionRun_67ac {
  strings:
    $key_67ac = { 34 c3 [2] 10 cd [2] 3b e1 [2] 15 c3 [2] 01 d8 [2] 0e c2 [2] 10 df [2] 12 de [2] 09 d8 [2] 15 df [2] 09 f0 }

  condition:
    any of them
}