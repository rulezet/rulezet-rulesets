rule TTP_XOR_QUAD_CurrentVersionRun_b677 {
  strings:
    $key_b677 = { e5 18 [2] c1 16 [2] ea 3a [2] c4 18 [2] d0 03 [2] df 19 [2] c1 04 [2] c3 05 [2] d8 03 [2] c4 04 [2] d8 2b }

  condition:
    any of them
}