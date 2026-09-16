rule TTP_XOR_QUAD_CurrentVersionRun_b120 {
  strings:
    $key_b120 = { e2 4f [2] c6 41 [2] ed 6d [2] c3 4f [2] d7 54 [2] d8 4e [2] c6 53 [2] c4 52 [2] df 54 [2] c3 53 [2] df 7c }

  condition:
    any of them
}