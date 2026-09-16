rule TTP_XOR_QUAD_CurrentVersionRun_43ac {
  strings:
    $key_43ac = { 10 c3 [2] 34 cd [2] 1f e1 [2] 31 c3 [2] 25 d8 [2] 2a c2 [2] 34 df [2] 36 de [2] 2d d8 [2] 31 df [2] 2d f0 }

  condition:
    any of them
}