rule TTP_XOR_QUAD_CurrentVersionRun_929a {
  strings:
    $key_929a = { c1 f5 [2] e5 fb [2] ce d7 [2] e0 f5 [2] f4 ee [2] fb f4 [2] e5 e9 [2] e7 e8 [2] fc ee [2] e0 e9 [2] fc c6 }

  condition:
    any of them
}