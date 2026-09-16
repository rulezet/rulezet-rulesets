rule TTP_XOR_QUAD_CurrentVersionRun_9b99 {
  strings:
    $key_9b99 = { c8 f6 [2] ec f8 [2] c7 d4 [2] e9 f6 [2] fd ed [2] f2 f7 [2] ec ea [2] ee eb [2] f5 ed [2] e9 ea [2] f5 c5 }

  condition:
    any of them
}