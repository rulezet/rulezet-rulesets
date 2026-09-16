rule TTP_XOR_QUAD_CurrentVersionRun_9186 {
  strings:
    $key_9186 = { c2 e9 [2] e6 e7 [2] cd cb [2] e3 e9 [2] f7 f2 [2] f8 e8 [2] e6 f5 [2] e4 f4 [2] ff f2 [2] e3 f5 [2] ff da }

  condition:
    any of them
}