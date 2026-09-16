rule TTP_XOR_QUAD_CurrentVersionRun_37ac {
  strings:
    $key_37ac = { 64 c3 [2] 40 cd [2] 6b e1 [2] 45 c3 [2] 51 d8 [2] 5e c2 [2] 40 df [2] 42 de [2] 59 d8 [2] 45 df [2] 59 f0 }

  condition:
    any of them
}