rule TTP_XOR_QUAD_CurrentVersionRun_fdce {
  strings:
    $key_fdce = { ae a1 [2] 8a af [2] a1 83 [2] 8f a1 [2] 9b ba [2] 94 a0 [2] 8a bd [2] 88 bc [2] 93 ba [2] 8f bd [2] 93 92 }

  condition:
    any of them
}