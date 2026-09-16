rule TTP_XOR_QUAD_CurrentVersionRun_b117 {
  strings:
    $key_b117 = { e2 78 [2] c6 76 [2] ed 5a [2] c3 78 [2] d7 63 [2] d8 79 [2] c6 64 [2] c4 65 [2] df 63 [2] c3 64 [2] df 4b }

  condition:
    any of them
}