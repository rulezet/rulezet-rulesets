rule TTP_XOR_QUAD_CurrentVersionRun_b631 {
  strings:
    $key_b631 = { e5 5e [2] c1 50 [2] ea 7c [2] c4 5e [2] d0 45 [2] df 5f [2] c1 42 [2] c3 43 [2] d8 45 [2] c4 42 [2] d8 6d }

  condition:
    any of them
}