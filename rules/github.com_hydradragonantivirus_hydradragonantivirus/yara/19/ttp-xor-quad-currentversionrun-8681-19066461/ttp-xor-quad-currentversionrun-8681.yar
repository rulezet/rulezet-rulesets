rule TTP_XOR_QUAD_CurrentVersionRun_8681 {
  strings:
    $key_8681 = { d5 ee [2] f1 e0 [2] da cc [2] f4 ee [2] e0 f5 [2] ef ef [2] f1 f2 [2] f3 f3 [2] e8 f5 [2] f4 f2 [2] e8 dd }

  condition:
    any of them
}