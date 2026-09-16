rule TTP_XOR_QUAD_CurrentVersionRun_b130 {
  strings:
    $key_b130 = { e2 5f [2] c6 51 [2] ed 7d [2] c3 5f [2] d7 44 [2] d8 5e [2] c6 43 [2] c4 42 [2] df 44 [2] c3 43 [2] df 6c }

  condition:
    any of them
}