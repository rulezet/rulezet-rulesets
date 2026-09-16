rule TTP_XOR_QUAD_CurrentVersionRun_b170 {
  strings:
    $key_b170 = { e2 1f [2] c6 11 [2] ed 3d [2] c3 1f [2] d7 04 [2] d8 1e [2] c6 03 [2] c4 02 [2] df 04 [2] c3 03 [2] df 2c }

  condition:
    any of them
}