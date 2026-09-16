rule TTP_XOR_QUAD_CurrentVersionRun_b1f6 {
  strings:
    $key_b1f6 = { e2 99 [2] c6 97 [2] ed bb [2] c3 99 [2] d7 82 [2] d8 98 [2] c6 85 [2] c4 84 [2] df 82 [2] c3 85 [2] df aa }

  condition:
    any of them
}