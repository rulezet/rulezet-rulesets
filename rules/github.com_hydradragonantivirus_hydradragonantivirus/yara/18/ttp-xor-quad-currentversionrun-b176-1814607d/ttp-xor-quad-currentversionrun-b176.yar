rule TTP_XOR_QUAD_CurrentVersionRun_b176 {
  strings:
    $key_b176 = { e2 19 [2] c6 17 [2] ed 3b [2] c3 19 [2] d7 02 [2] d8 18 [2] c6 05 [2] c4 04 [2] df 02 [2] c3 05 [2] df 2a }

  condition:
    any of them
}