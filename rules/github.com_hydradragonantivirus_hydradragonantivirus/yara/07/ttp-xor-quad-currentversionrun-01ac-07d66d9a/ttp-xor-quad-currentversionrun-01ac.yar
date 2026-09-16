rule TTP_XOR_QUAD_CurrentVersionRun_01ac {
  strings:
    $key_01ac = { 52 c3 [2] 76 cd [2] 5d e1 [2] 73 c3 [2] 67 d8 [2] 68 c2 [2] 76 df [2] 74 de [2] 6f d8 [2] 73 df [2] 6f f0 }

  condition:
    any of them
}