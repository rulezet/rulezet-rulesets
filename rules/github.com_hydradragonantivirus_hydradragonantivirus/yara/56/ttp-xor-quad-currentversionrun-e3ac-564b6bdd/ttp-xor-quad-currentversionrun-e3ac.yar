rule TTP_XOR_QUAD_CurrentVersionRun_e3ac {
  strings:
    $key_e3ac = { b0 c3 [2] 94 cd [2] bf e1 [2] 91 c3 [2] 85 d8 [2] 8a c2 [2] 94 df [2] 96 de [2] 8d d8 [2] 91 df [2] 8d f0 }

  condition:
    any of them
}