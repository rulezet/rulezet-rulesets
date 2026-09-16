rule TTP_XOR_QUAD_CurrentVersionRun_9187 {
  strings:
    $key_9187 = { c2 e8 [2] e6 e6 [2] cd ca [2] e3 e8 [2] f7 f3 [2] f8 e9 [2] e6 f4 [2] e4 f5 [2] ff f3 [2] e3 f4 [2] ff db }

  condition:
    any of them
}