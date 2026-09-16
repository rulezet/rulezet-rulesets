rule TTP_XOR_QUAD_CurrentVersionRun_46ac {
  strings:
    $key_46ac = { 15 c3 [2] 31 cd [2] 1a e1 [2] 34 c3 [2] 20 d8 [2] 2f c2 [2] 31 df [2] 33 de [2] 28 d8 [2] 34 df [2] 28 f0 }

  condition:
    any of them
}