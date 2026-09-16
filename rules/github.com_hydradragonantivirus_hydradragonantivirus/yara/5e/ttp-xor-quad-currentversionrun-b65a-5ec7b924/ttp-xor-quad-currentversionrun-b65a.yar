rule TTP_XOR_QUAD_CurrentVersionRun_b65a {
  strings:
    $key_b65a = { e5 35 [2] c1 3b [2] ea 17 [2] c4 35 [2] d0 2e [2] df 34 [2] c1 29 [2] c3 28 [2] d8 2e [2] c4 29 [2] d8 06 }

  condition:
    any of them
}