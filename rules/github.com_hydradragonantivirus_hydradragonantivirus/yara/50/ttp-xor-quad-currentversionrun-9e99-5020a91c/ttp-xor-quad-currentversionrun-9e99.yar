rule TTP_XOR_QUAD_CurrentVersionRun_9e99 {
  strings:
    $key_9e99 = { cd f6 [2] e9 f8 [2] c2 d4 [2] ec f6 [2] f8 ed [2] f7 f7 [2] e9 ea [2] eb eb [2] f0 ed [2] ec ea [2] f0 c5 }

  condition:
    any of them
}