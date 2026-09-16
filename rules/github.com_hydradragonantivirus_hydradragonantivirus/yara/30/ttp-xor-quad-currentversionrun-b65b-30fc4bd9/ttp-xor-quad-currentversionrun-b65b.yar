rule TTP_XOR_QUAD_CurrentVersionRun_b65b {
  strings:
    $key_b65b = { e5 34 [2] c1 3a [2] ea 16 [2] c4 34 [2] d0 2f [2] df 35 [2] c1 28 [2] c3 29 [2] d8 2f [2] c4 28 [2] d8 07 }

  condition:
    any of them
}