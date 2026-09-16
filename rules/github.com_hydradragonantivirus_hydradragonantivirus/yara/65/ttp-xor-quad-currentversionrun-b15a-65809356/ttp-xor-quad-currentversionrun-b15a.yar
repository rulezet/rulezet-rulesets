rule TTP_XOR_QUAD_CurrentVersionRun_b15a {
  strings:
    $key_b15a = { e2 35 [2] c6 3b [2] ed 17 [2] c3 35 [2] d7 2e [2] d8 34 [2] c6 29 [2] c4 28 [2] df 2e [2] c3 29 [2] df 06 }

  condition:
    any of them
}