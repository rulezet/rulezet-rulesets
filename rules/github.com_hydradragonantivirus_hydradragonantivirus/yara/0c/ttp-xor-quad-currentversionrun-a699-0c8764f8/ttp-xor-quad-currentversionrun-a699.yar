rule TTP_XOR_QUAD_CurrentVersionRun_a699 {
  strings:
    $key_a699 = { f5 f6 [2] d1 f8 [2] fa d4 [2] d4 f6 [2] c0 ed [2] cf f7 [2] d1 ea [2] d3 eb [2] c8 ed [2] d4 ea [2] c8 c5 }

  condition:
    any of them
}