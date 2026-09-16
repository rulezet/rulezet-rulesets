rule TTP_XOR_QUAD_CurrentVersionRun_b10b {
  strings:
    $key_b10b = { e2 64 [2] c6 6a [2] ed 46 [2] c3 64 [2] d7 7f [2] d8 65 [2] c6 78 [2] c4 79 [2] df 7f [2] c3 78 [2] df 57 }

  condition:
    any of them
}