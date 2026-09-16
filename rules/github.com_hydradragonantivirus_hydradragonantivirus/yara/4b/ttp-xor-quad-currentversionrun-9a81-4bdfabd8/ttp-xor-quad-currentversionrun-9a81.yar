rule TTP_XOR_QUAD_CurrentVersionRun_9a81 {
  strings:
    $key_9a81 = { c9 ee [2] ed e0 [2] c6 cc [2] e8 ee [2] fc f5 [2] f3 ef [2] ed f2 [2] ef f3 [2] f4 f5 [2] e8 f2 [2] f4 dd }

  condition:
    any of them
}