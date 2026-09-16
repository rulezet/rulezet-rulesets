rule TTP_XOR_QUAD_CurrentVersionRun_b676 {
  strings:
    $key_b676 = { e5 19 [2] c1 17 [2] ea 3b [2] c4 19 [2] d0 02 [2] df 18 [2] c1 05 [2] c3 04 [2] d8 02 [2] c4 05 [2] d8 2a }

  condition:
    any of them
}