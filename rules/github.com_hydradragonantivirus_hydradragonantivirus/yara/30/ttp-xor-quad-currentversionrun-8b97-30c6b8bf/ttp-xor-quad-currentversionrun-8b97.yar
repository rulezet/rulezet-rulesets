rule TTP_XOR_QUAD_CurrentVersionRun_8b97 {
  strings:
    $key_8b97 = { d8 f8 [2] fc f6 [2] d7 da [2] f9 f8 [2] ed e3 [2] e2 f9 [2] fc e4 [2] fe e5 [2] e5 e3 [2] f9 e4 [2] e5 cb }

  condition:
    any of them
}