rule TTP_XOR_QUAD_CurrentVersionRun_77ac {
  strings:
    $key_77ac = { 24 c3 [2] 00 cd [2] 2b e1 [2] 05 c3 [2] 11 d8 [2] 1e c2 [2] 00 df [2] 02 de [2] 19 d8 [2] 05 df [2] 19 f0 }

  condition:
    any of them
}