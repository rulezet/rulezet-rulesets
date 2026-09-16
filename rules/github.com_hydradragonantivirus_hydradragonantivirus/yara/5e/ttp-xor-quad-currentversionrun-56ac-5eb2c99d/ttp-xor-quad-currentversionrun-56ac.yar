rule TTP_XOR_QUAD_CurrentVersionRun_56ac {
  strings:
    $key_56ac = { 05 c3 [2] 21 cd [2] 0a e1 [2] 24 c3 [2] 30 d8 [2] 3f c2 [2] 21 df [2] 23 de [2] 38 d8 [2] 24 df [2] 38 f0 }

  condition:
    any of them
}