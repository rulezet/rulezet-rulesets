rule TTP_XOR_QUAD_CurrentVersionRun_b100 {
  strings:
    $key_b100 = { e2 6f [2] c6 61 [2] ed 4d [2] c3 6f [2] d7 74 [2] d8 6e [2] c6 73 [2] c4 72 [2] df 74 [2] c3 73 [2] df 5c }

  condition:
    any of them
}