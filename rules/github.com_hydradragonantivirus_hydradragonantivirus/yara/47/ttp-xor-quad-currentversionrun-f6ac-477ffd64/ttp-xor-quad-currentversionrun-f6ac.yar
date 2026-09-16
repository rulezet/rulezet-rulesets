rule TTP_XOR_QUAD_CurrentVersionRun_f6ac {
  strings:
    $key_f6ac = { a5 c3 [2] 81 cd [2] aa e1 [2] 84 c3 [2] 90 d8 [2] 9f c2 [2] 81 df [2] 83 de [2] 98 d8 [2] 84 df [2] 98 f0 }

  condition:
    any of them
}