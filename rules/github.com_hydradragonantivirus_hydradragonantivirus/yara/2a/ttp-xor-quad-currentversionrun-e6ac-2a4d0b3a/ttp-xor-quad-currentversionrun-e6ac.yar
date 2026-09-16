rule TTP_XOR_QUAD_CurrentVersionRun_e6ac {
  strings:
    $key_e6ac = { b5 c3 [2] 91 cd [2] ba e1 [2] 94 c3 [2] 80 d8 [2] 8f c2 [2] 91 df [2] 93 de [2] 88 d8 [2] 94 df [2] 88 f0 }

  condition:
    any of them
}