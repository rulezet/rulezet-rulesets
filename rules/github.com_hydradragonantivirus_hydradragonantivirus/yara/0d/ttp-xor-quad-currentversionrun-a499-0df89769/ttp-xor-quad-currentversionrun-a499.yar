rule TTP_XOR_QUAD_CurrentVersionRun_a499 {
  strings:
    $key_a499 = { f7 f6 [2] d3 f8 [2] f8 d4 [2] d6 f6 [2] c2 ed [2] cd f7 [2] d3 ea [2] d1 eb [2] ca ed [2] d6 ea [2] ca c5 }

  condition:
    any of them
}