rule TTP_XOR_QUAD_CurrentVersionRun_b659 {
  strings:
    $key_b659 = { e5 36 [2] c1 38 [2] ea 14 [2] c4 36 [2] d0 2d [2] df 37 [2] c1 2a [2] c3 2b [2] d8 2d [2] c4 2a [2] d8 05 }

  condition:
    any of them
}