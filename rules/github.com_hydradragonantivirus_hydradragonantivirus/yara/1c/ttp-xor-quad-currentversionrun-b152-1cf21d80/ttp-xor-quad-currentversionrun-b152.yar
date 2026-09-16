rule TTP_XOR_QUAD_CurrentVersionRun_b152 {
  strings:
    $key_b152 = { e2 3d [2] c6 33 [2] ed 1f [2] c3 3d [2] d7 26 [2] d8 3c [2] c6 21 [2] c4 20 [2] df 26 [2] c3 21 [2] df 0e }

  condition:
    any of them
}