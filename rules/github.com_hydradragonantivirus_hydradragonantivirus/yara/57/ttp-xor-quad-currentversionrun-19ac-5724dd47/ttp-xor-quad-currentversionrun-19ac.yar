rule TTP_XOR_QUAD_CurrentVersionRun_19ac {
  strings:
    $key_19ac = { 4a c3 [2] 6e cd [2] 45 e1 [2] 6b c3 [2] 7f d8 [2] 70 c2 [2] 6e df [2] 6c de [2] 77 d8 [2] 6b df [2] 77 f0 }

  condition:
    any of them
}