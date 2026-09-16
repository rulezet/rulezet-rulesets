rule TTP_XOR_QUAD_CurrentVersionRun_8b9d {
  strings:
    $key_8b9d = { d8 f2 [2] fc fc [2] d7 d0 [2] f9 f2 [2] ed e9 [2] e2 f3 [2] fc ee [2] fe ef [2] e5 e9 [2] f9 ee [2] e5 c1 }

  condition:
    any of them
}