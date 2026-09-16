rule TTP_XOR_QUAD_CurrentVersionRun_b6ac {
  strings:
    $key_b6ac = { e5 c3 [2] c1 cd [2] ea e1 [2] c4 c3 [2] d0 d8 [2] df c2 [2] c1 df [2] c3 de [2] d8 d8 [2] c4 df [2] d8 f0 }

  condition:
    any of them
}