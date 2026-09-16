rule TTP_XOR_QUAD_CurrentVersionRun_b12c {
  strings:
    $key_b12c = { e2 43 [2] c6 4d [2] ed 61 [2] c3 43 [2] d7 58 [2] d8 42 [2] c6 5f [2] c4 5e [2] df 58 [2] c3 5f [2] df 70 }

  condition:
    any of them
}