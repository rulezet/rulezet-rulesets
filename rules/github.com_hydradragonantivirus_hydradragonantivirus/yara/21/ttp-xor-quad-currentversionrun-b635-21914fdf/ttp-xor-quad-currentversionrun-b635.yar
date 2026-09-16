rule TTP_XOR_QUAD_CurrentVersionRun_b635 {
  strings:
    $key_b635 = { e5 5a [2] c1 54 [2] ea 78 [2] c4 5a [2] d0 41 [2] df 5b [2] c1 46 [2] c3 47 [2] d8 41 [2] c4 46 [2] d8 69 }

  condition:
    any of them
}