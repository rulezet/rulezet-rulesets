rule TTP_XOR_QUAD_CurrentVersionRun_49ac {
  strings:
    $key_49ac = { 1a c3 [2] 3e cd [2] 15 e1 [2] 3b c3 [2] 2f d8 [2] 20 c2 [2] 3e df [2] 3c de [2] 27 d8 [2] 3b df [2] 27 f0 }

  condition:
    any of them
}