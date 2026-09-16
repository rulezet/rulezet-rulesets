rule TTP_XOR_QUAD_CurrentVersionRun_b617 {
  strings:
    $key_b617 = { e5 78 [2] c1 76 [2] ea 5a [2] c4 78 [2] d0 63 [2] df 79 [2] c1 64 [2] c3 65 [2] d8 63 [2] c4 64 [2] d8 4b }

  condition:
    any of them
}