rule TTP_XOR_QUAD_CurrentVersionRun_dbd3 {
  strings:
    $key_dbd3 = { 88 bc [2] ac b2 [2] 87 9e [2] a9 bc [2] bd a7 [2] b2 bd [2] ac a0 [2] ae a1 [2] b5 a7 [2] a9 a0 [2] b5 8f }

  condition:
    any of them
}