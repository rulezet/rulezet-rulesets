rule TTP_XOR_QUAD_CurrentVersionRun_8f84 {
  strings:
    $key_8f84 = { dc eb [2] f8 e5 [2] d3 c9 [2] fd eb [2] e9 f0 [2] e6 ea [2] f8 f7 [2] fa f6 [2] e1 f0 [2] fd f7 [2] e1 d8 }

  condition:
    any of them
}