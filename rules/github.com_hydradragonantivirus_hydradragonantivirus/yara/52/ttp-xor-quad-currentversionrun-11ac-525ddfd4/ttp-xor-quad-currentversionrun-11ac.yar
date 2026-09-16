rule TTP_XOR_QUAD_CurrentVersionRun_11ac {
  strings:
    $key_11ac = { 42 c3 [2] 66 cd [2] 4d e1 [2] 63 c3 [2] 77 d8 [2] 78 c2 [2] 66 df [2] 64 de [2] 7f d8 [2] 63 df [2] 7f f0 }

  condition:
    any of them
}