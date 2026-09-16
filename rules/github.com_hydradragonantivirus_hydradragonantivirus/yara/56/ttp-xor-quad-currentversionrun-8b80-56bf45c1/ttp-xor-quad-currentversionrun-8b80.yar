rule TTP_XOR_QUAD_CurrentVersionRun_8b80 {
  strings:
    $key_8b80 = { d8 ef [2] fc e1 [2] d7 cd [2] f9 ef [2] ed f4 [2] e2 ee [2] fc f3 [2] fe f2 [2] e5 f4 [2] f9 f3 [2] e5 dc }

  condition:
    any of them
}