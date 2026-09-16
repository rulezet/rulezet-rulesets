rule TTP_XOR_QUAD_CurrentVersionRun_b13b {
  strings:
    $key_b13b = { e2 54 [2] c6 5a [2] ed 76 [2] c3 54 [2] d7 4f [2] d8 55 [2] c6 48 [2] c4 49 [2] df 4f [2] c3 48 [2] df 67 }

  condition:
    any of them
}