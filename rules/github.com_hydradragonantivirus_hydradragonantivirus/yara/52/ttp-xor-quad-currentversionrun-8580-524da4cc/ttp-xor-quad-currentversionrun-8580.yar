rule TTP_XOR_QUAD_CurrentVersionRun_8580 {
  strings:
    $key_8580 = { d6 ef [2] f2 e1 [2] d9 cd [2] f7 ef [2] e3 f4 [2] ec ee [2] f2 f3 [2] f0 f2 [2] eb f4 [2] f7 f3 [2] eb dc }

  condition:
    any of them
}