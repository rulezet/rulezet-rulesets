rule TTP_XOR_QUAD_CurrentVersionRun_9185 {
  strings:
    $key_9185 = { c2 ea [2] e6 e4 [2] cd c8 [2] e3 ea [2] f7 f1 [2] f8 eb [2] e6 f6 [2] e4 f7 [2] ff f1 [2] e3 f6 [2] ff d9 }

  condition:
    any of them
}