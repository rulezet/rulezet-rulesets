rule TTP_XOR_QUAD_CurrentVersionRun_b7a6 {
  strings:
    $key_b7a6 = { e4 c9 [2] c0 c7 [2] eb eb [2] c5 c9 [2] d1 d2 [2] de c8 [2] c0 d5 [2] c2 d4 [2] d9 d2 [2] c5 d5 [2] d9 fa }

  condition:
    any of them
}