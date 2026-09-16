rule TTP_XOR_QUAD_CurrentVersionRun_8f85 {
  strings:
    $key_8f85 = { dc ea [2] f8 e4 [2] d3 c8 [2] fd ea [2] e9 f1 [2] e6 eb [2] f8 f6 [2] fa f7 [2] e1 f1 [2] fd f6 [2] e1 d9 }

  condition:
    any of them
}