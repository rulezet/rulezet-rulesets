rule TTP_XOR_QUAD_CurrentVersionRun_b880 {
  strings:
    $key_b880 = { eb ef [2] cf e1 [2] e4 cd [2] ca ef [2] de f4 [2] d1 ee [2] cf f3 [2] cd f2 [2] d6 f4 [2] ca f3 [2] d6 dc }

  condition:
    any of them
}