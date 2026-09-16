rule TTP_XOR_QUAD_CurrentVersionRun_f3ac {
  strings:
    $key_f3ac = { a0 c3 [2] 84 cd [2] af e1 [2] 81 c3 [2] 95 d8 [2] 9a c2 [2] 84 df [2] 86 de [2] 9d d8 [2] 81 df [2] 9d f0 }

  condition:
    any of them
}