rule TTP_XOR_QUAD_CurrentVersionRun_b626 {
  strings:
    $key_b626 = { e5 49 [2] c1 47 [2] ea 6b [2] c4 49 [2] d0 52 [2] df 48 [2] c1 55 [2] c3 54 [2] d8 52 [2] c4 55 [2] d8 7a }

  condition:
    any of them
}