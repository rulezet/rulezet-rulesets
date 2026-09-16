rule TTP_XOR_QUAD_CurrentVersionRun_9181 {
  strings:
    $key_9181 = { c2 ee [2] e6 e0 [2] cd cc [2] e3 ee [2] f7 f5 [2] f8 ef [2] e6 f2 [2] e4 f3 [2] ff f5 [2] e3 f2 [2] ff dd }

  condition:
    any of them
}