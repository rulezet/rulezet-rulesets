rule TTP_XOR_QUAD_CurrentVersionRun_8399 {
  strings:
    $key_8399 = { d0 f6 [2] f4 f8 [2] df d4 [2] f1 f6 [2] e5 ed [2] ea f7 [2] f4 ea [2] f6 eb [2] ed ed [2] f1 ea [2] ed c5 }

  condition:
    any of them
}