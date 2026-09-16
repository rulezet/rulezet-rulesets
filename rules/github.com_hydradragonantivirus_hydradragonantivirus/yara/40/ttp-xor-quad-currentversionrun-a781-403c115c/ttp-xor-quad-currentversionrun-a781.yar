rule TTP_XOR_QUAD_CurrentVersionRun_a781 {
  strings:
    $key_a781 = { f4 ee [2] d0 e0 [2] fb cc [2] d5 ee [2] c1 f5 [2] ce ef [2] d0 f2 [2] d2 f3 [2] c9 f5 [2] d5 f2 [2] c9 dd }

  condition:
    any of them
}