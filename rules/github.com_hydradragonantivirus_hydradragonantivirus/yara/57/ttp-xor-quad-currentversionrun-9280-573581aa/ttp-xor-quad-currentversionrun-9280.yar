rule TTP_XOR_QUAD_CurrentVersionRun_9280 {
  strings:
    $key_9280 = { c1 ef [2] e5 e1 [2] ce cd [2] e0 ef [2] f4 f4 [2] fb ee [2] e5 f3 [2] e7 f2 [2] fc f4 [2] e0 f3 [2] fc dc }

  condition:
    any of them
}