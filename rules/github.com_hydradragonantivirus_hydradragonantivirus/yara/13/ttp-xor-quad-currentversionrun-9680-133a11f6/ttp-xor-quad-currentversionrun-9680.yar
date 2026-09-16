rule TTP_XOR_QUAD_CurrentVersionRun_9680 {
  strings:
    $key_9680 = { c5 ef [2] e1 e1 [2] ca cd [2] e4 ef [2] f0 f4 [2] ff ee [2] e1 f3 [2] e3 f2 [2] f8 f4 [2] e4 f3 [2] f8 dc }

  condition:
    any of them
}