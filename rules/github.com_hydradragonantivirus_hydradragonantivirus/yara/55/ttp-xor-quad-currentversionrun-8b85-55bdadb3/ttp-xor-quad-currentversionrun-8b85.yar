rule TTP_XOR_QUAD_CurrentVersionRun_8b85 {
  strings:
    $key_8b85 = { d8 ea [2] fc e4 [2] d7 c8 [2] f9 ea [2] ed f1 [2] e2 eb [2] fc f6 [2] fe f7 [2] e5 f1 [2] f9 f6 [2] e5 d9 }

  condition:
    any of them
}