rule TTP_XOR_QUAD_CurrentVersionRun_b654 {
  strings:
    $key_b654 = { e5 3b [2] c1 35 [2] ea 19 [2] c4 3b [2] d0 20 [2] df 3a [2] c1 27 [2] c3 26 [2] d8 20 [2] c4 27 [2] d8 08 }

  condition:
    any of them
}