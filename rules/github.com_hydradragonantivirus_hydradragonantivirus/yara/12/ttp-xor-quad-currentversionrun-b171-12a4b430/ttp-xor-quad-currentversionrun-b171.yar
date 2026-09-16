rule TTP_XOR_QUAD_CurrentVersionRun_b171 {
  strings:
    $key_b171 = { e2 1e [2] c6 10 [2] ed 3c [2] c3 1e [2] d7 05 [2] d8 1f [2] c6 02 [2] c4 03 [2] df 05 [2] c3 02 [2] df 2d }

  condition:
    any of them
}