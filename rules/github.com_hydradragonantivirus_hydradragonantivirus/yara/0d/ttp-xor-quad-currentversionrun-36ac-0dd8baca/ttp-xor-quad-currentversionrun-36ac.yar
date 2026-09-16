rule TTP_XOR_QUAD_CurrentVersionRun_36ac {
  strings:
    $key_36ac = { 65 c3 [2] 41 cd [2] 6a e1 [2] 44 c3 [2] 50 d8 [2] 5f c2 [2] 41 df [2] 43 de [2] 58 d8 [2] 44 df [2] 58 f0 }

  condition:
    any of them
}