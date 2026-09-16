rule TTP_XOR_QUAD_CurrentVersionRun_8599 {
  strings:
    $key_8599 = { d6 f6 [2] f2 f8 [2] d9 d4 [2] f7 f6 [2] e3 ed [2] ec f7 [2] f2 ea [2] f0 eb [2] eb ed [2] f7 ea [2] eb c5 }

  condition:
    any of them
}