rule TTP_XOR_QUAD_CurrentVersionRun_9a99 {
  strings:
    $key_9a99 = { c9 f6 [2] ed f8 [2] c6 d4 [2] e8 f6 [2] fc ed [2] f3 f7 [2] ed ea [2] ef eb [2] f4 ed [2] e8 ea [2] f4 c5 }

  condition:
    any of them
}