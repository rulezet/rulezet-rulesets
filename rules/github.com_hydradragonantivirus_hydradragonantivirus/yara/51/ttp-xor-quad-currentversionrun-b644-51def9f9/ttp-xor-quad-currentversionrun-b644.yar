rule TTP_XOR_QUAD_CurrentVersionRun_b644 {
  strings:
    $key_b644 = { e5 2b [2] c1 25 [2] ea 09 [2] c4 2b [2] d0 30 [2] df 2a [2] c1 37 [2] c3 36 [2] d8 30 [2] c4 37 [2] d8 18 }

  condition:
    any of them
}