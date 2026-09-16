rule TTP_XOR_QUAD_CurrentVersionRun_b778 {
  strings:
    $key_b778 = { e4 17 [2] c0 19 [2] eb 35 [2] c5 17 [2] d1 0c [2] de 16 [2] c0 0b [2] c2 0a [2] d9 0c [2] c5 0b [2] d9 24 }

  condition:
    any of them
}