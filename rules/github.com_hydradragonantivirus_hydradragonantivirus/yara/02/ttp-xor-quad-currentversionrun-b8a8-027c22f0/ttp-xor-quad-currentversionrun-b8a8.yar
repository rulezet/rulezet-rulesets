rule TTP_XOR_QUAD_CurrentVersionRun_b8a8 {
  strings:
    $key_b8a8 = { eb c7 [2] cf c9 [2] e4 e5 [2] ca c7 [2] de dc [2] d1 c6 [2] cf db [2] cd da [2] d6 dc [2] ca db [2] d6 f4 }

  condition:
    any of them
}