rule TTP_XOR_QUAD_CurrentVersionRun_13ac {
  strings:
    $key_13ac = { 40 c3 [2] 64 cd [2] 4f e1 [2] 61 c3 [2] 75 d8 [2] 7a c2 [2] 64 df [2] 66 de [2] 7d d8 [2] 61 df [2] 7d f0 }

  condition:
    any of them
}