rule TTP_XOR_QUAD_CurrentVersionRun_d6ac {
  strings:
    $key_d6ac = { 85 c3 [2] a1 cd [2] 8a e1 [2] a4 c3 [2] b0 d8 [2] bf c2 [2] a1 df [2] a3 de [2] b8 d8 [2] a4 df [2] b8 f0 }

  condition:
    any of them
}