rule TTP_XOR_QUAD_CurrentVersionRun_9999 {
  strings:
    $key_9999 = { ca f6 [2] ee f8 [2] c5 d4 [2] eb f6 [2] ff ed [2] f0 f7 [2] ee ea [2] ec eb [2] f7 ed [2] eb ea [2] f7 c5 }

  condition:
    any of them
}