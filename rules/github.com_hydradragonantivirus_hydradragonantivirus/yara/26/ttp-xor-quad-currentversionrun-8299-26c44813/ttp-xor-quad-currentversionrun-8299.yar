rule TTP_XOR_QUAD_CurrentVersionRun_8299 {
  strings:
    $key_8299 = { d1 f6 [2] f5 f8 [2] de d4 [2] f0 f6 [2] e4 ed [2] eb f7 [2] f5 ea [2] f7 eb [2] ec ed [2] f0 ea [2] ec c5 }

  condition:
    any of them
}