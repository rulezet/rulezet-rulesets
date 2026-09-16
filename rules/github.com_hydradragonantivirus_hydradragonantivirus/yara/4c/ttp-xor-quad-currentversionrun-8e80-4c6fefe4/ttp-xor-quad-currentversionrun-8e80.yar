rule TTP_XOR_QUAD_CurrentVersionRun_8e80 {
  strings:
    $key_8e80 = { dd ef [2] f9 e1 [2] d2 cd [2] fc ef [2] e8 f4 [2] e7 ee [2] f9 f3 [2] fb f2 [2] e0 f4 [2] fc f3 [2] e0 dc }

  condition:
    any of them
}