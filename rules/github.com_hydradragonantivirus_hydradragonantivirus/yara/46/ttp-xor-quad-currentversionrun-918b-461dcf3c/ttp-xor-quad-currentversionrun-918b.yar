rule TTP_XOR_QUAD_CurrentVersionRun_918b {
  strings:
    $key_918b = { c2 e4 [2] e6 ea [2] cd c6 [2] e3 e4 [2] f7 ff [2] f8 e5 [2] e6 f8 [2] e4 f9 [2] ff ff [2] e3 f8 [2] ff d7 }

  condition:
    any of them
}