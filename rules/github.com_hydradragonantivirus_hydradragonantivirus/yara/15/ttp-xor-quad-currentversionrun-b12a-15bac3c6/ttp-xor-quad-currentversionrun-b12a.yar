rule TTP_XOR_QUAD_CurrentVersionRun_b12a {
  strings:
    $key_b12a = { e2 45 [2] c6 4b [2] ed 67 [2] c3 45 [2] d7 5e [2] d8 44 [2] c6 59 [2] c4 58 [2] df 5e [2] c3 59 [2] df 76 }

  condition:
    any of them
}