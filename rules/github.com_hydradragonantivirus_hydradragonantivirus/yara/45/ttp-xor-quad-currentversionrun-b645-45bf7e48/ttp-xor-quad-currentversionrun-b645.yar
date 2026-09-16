rule TTP_XOR_QUAD_CurrentVersionRun_b645 {
  strings:
    $key_b645 = { e5 2a [2] c1 24 [2] ea 08 [2] c4 2a [2] d0 31 [2] df 2b [2] c1 36 [2] c3 37 [2] d8 31 [2] c4 36 [2] d8 19 }

  condition:
    any of them
}