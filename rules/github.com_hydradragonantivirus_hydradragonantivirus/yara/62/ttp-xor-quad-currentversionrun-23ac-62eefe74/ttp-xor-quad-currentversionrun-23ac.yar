rule TTP_XOR_QUAD_CurrentVersionRun_23ac {
  strings:
    $key_23ac = { 70 c3 [2] 54 cd [2] 7f e1 [2] 51 c3 [2] 45 d8 [2] 4a c2 [2] 54 df [2] 56 de [2] 4d d8 [2] 51 df [2] 4d f0 }

  condition:
    any of them
}