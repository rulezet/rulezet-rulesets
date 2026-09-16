rule TTP_XOR_QUAD_CurrentVersionRun_b141 {
  strings:
    $key_b141 = { e2 2e [2] c6 20 [2] ed 0c [2] c3 2e [2] d7 35 [2] d8 2f [2] c6 32 [2] c4 33 [2] df 35 [2] c3 32 [2] df 1d }

  condition:
    any of them
}