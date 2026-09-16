rule TTP_XOR_QUAD_CurrentVersionRun_91e0 {
  strings:
    $key_91e0 = { c2 8f [2] e6 81 [2] cd ad [2] e3 8f [2] f7 94 [2] f8 8e [2] e6 93 [2] e4 92 [2] ff 94 [2] e3 93 [2] ff bc }

  condition:
    any of them
}