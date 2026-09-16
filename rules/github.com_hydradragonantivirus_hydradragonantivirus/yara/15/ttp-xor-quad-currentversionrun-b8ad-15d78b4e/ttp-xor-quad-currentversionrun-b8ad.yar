rule TTP_XOR_QUAD_CurrentVersionRun_b8ad {
  strings:
    $key_b8ad = { eb c2 [2] cf cc [2] e4 e0 [2] ca c2 [2] de d9 [2] d1 c3 [2] cf de [2] cd df [2] d6 d9 [2] ca de [2] d6 f1 }

  condition:
    any of them
}