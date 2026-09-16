rule TTP_XOR_QUAD_CurrentVersionRun_b17c {
  strings:
    $key_b17c = { e2 13 [2] c6 1d [2] ed 31 [2] c3 13 [2] d7 08 [2] d8 12 [2] c6 0f [2] c4 0e [2] df 08 [2] c3 0f [2] df 20 }

  condition:
    any of them
}