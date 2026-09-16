rule TTP_XOR_QUAD_CurrentVersionRun_8499 {
  strings:
    $key_8499 = { d7 f6 [2] f3 f8 [2] d8 d4 [2] f6 f6 [2] e2 ed [2] ed f7 [2] f3 ea [2] f1 eb [2] ea ed [2] f6 ea [2] ea c5 }

  condition:
    any of them
}