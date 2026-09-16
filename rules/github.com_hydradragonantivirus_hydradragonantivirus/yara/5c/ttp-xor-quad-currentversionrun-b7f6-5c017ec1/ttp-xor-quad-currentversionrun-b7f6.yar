rule TTP_XOR_QUAD_CurrentVersionRun_b7f6 {
  strings:
    $key_b7f6 = { e4 99 [2] c0 97 [2] eb bb [2] c5 99 [2] d1 82 [2] de 98 [2] c0 85 [2] c2 84 [2] d9 82 [2] c5 85 [2] d9 aa }

  condition:
    any of them
}