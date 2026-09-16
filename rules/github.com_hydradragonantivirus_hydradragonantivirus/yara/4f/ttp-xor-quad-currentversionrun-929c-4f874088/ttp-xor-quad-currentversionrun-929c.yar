rule TTP_XOR_QUAD_CurrentVersionRun_929c {
  strings:
    $key_929c = { c1 f3 [2] e5 fd [2] ce d1 [2] e0 f3 [2] f4 e8 [2] fb f2 [2] e5 ef [2] e7 ee [2] fc e8 [2] e0 ef [2] fc c0 }

  condition:
    any of them
}