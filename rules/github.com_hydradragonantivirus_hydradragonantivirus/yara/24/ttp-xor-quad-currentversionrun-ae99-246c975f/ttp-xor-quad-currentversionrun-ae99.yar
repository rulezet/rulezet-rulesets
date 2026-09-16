rule TTP_XOR_QUAD_CurrentVersionRun_ae99 {
  strings:
    $key_ae99 = { fd f6 [2] d9 f8 [2] f2 d4 [2] dc f6 [2] c8 ed [2] c7 f7 [2] d9 ea [2] db eb [2] c0 ed [2] dc ea [2] c0 c5 }

  condition:
    any of them
}