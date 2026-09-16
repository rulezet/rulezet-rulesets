rule TTP_XOR_QUAD_CurrentVersionRun_59ac {
  strings:
    $key_59ac = { 0a c3 [2] 2e cd [2] 05 e1 [2] 2b c3 [2] 3f d8 [2] 30 c2 [2] 2e df [2] 2c de [2] 37 d8 [2] 2b df [2] 37 f0 }

  condition:
    any of them
}