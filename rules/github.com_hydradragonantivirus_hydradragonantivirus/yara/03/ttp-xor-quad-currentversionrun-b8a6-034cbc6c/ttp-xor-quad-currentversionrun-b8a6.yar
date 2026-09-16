rule TTP_XOR_QUAD_CurrentVersionRun_b8a6 {
  strings:
    $key_b8a6 = { eb c9 [2] cf c7 [2] e4 eb [2] ca c9 [2] de d2 [2] d1 c8 [2] cf d5 [2] cd d4 [2] d6 d2 [2] ca d5 [2] d6 fa }

  condition:
    any of them
}