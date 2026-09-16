rule TTP_XOR_QUAD_CurrentVersionRun_b8a2 {
  strings:
    $key_b8a2 = { eb cd [2] cf c3 [2] e4 ef [2] ca cd [2] de d6 [2] d1 cc [2] cf d1 [2] cd d0 [2] d6 d6 [2] ca d1 [2] d6 fe }

  condition:
    any of them
}