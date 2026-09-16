rule TTP_XOR_QUAD_CurrentVersionRun_b6f6 {
  strings:
    $key_b6f6 = { e5 99 [2] c1 97 [2] ea bb [2] c4 99 [2] d0 82 [2] df 98 [2] c1 85 [2] c3 84 [2] d8 82 [2] c4 85 [2] d8 aa }

  condition:
    any of them
}