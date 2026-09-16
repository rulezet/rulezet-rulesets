rule TTP_XOR_QUAD_CurrentVersionRun_b656 {
  strings:
    $key_b656 = { e5 39 [2] c1 37 [2] ea 1b [2] c4 39 [2] d0 22 [2] df 38 [2] c1 25 [2] c3 24 [2] d8 22 [2] c4 25 [2] d8 0a }

  condition:
    any of them
}