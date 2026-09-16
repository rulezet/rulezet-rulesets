rule TTP_XOR_QUAD_CurrentVersionRun_b111 {
  strings:
    $key_b111 = { e2 7e [2] c6 70 [2] ed 5c [2] c3 7e [2] d7 65 [2] d8 7f [2] c6 62 [2] c4 63 [2] df 65 [2] c3 62 [2] df 4d }

  condition:
    any of them
}