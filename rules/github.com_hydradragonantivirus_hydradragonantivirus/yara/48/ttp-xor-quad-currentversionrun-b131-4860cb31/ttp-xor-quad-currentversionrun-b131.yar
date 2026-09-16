rule TTP_XOR_QUAD_CurrentVersionRun_b131 {
  strings:
    $key_b131 = { e2 5e [2] c6 50 [2] ed 7c [2] c3 5e [2] d7 45 [2] d8 5f [2] c6 42 [2] c4 43 [2] df 45 [2] c3 42 [2] df 6d }

  condition:
    any of them
}