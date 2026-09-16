rule TTP_XOR_QUAD_CurrentVersionRun_9484 {
  strings:
    $key_9484 = { c7 eb [2] e3 e5 [2] c8 c9 [2] e6 eb [2] f2 f0 [2] fd ea [2] e3 f7 [2] e1 f6 [2] fa f0 [2] e6 f7 [2] fa d8 }

  condition:
    any of them
}