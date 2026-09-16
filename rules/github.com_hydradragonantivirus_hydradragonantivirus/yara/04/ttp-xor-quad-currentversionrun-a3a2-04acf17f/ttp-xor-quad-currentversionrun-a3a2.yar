rule TTP_XOR_QUAD_CurrentVersionRun_a3a2 {
  strings:
    $key_a3a2 = { f0 cd [2] d4 c3 [2] ff ef [2] d1 cd [2] c5 d6 [2] ca cc [2] d4 d1 [2] d6 d0 [2] cd d6 [2] d1 d1 [2] cd fe }

  condition:
    any of them
}