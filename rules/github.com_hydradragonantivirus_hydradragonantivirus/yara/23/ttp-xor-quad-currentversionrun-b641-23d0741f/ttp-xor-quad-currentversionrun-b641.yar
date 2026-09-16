rule TTP_XOR_QUAD_CurrentVersionRun_b641 {
  strings:
    $key_b641 = { e5 2e [2] c1 20 [2] ea 0c [2] c4 2e [2] d0 35 [2] df 2f [2] c1 32 [2] c3 33 [2] d8 35 [2] c4 32 [2] d8 1d }

  condition:
    any of them
}