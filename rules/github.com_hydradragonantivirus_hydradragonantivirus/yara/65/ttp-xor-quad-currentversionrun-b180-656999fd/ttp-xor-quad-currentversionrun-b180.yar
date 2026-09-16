rule TTP_XOR_QUAD_CurrentVersionRun_b180 {
  strings:
    $key_b180 = { e2 ef [2] c6 e1 [2] ed cd [2] c3 ef [2] d7 f4 [2] d8 ee [2] c6 f3 [2] c4 f2 [2] df f4 [2] c3 f3 [2] df dc }

  condition:
    any of them
}