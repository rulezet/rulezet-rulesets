rule TTP_XOR_QUAD_CurrentVersionRun_8e85 {
  strings:
    $key_8e85 = { dd ea [2] f9 e4 [2] d2 c8 [2] fc ea [2] e8 f1 [2] e7 eb [2] f9 f6 [2] fb f7 [2] e0 f1 [2] fc f6 [2] e0 d9 }

  condition:
    any of them
}