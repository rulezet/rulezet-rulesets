rule TTP_XOR_QUAD_CurrentVersionRun_748b {
  strings:
    $key_748b = { 27 e4 [2] 03 ea [2] 28 c6 [2] 06 e4 [2] 12 ff [2] 1d e5 [2] 03 f8 [2] 01 f9 [2] 1a ff [2] 06 f8 [2] 1a d7 }

  condition:
    any of them
}