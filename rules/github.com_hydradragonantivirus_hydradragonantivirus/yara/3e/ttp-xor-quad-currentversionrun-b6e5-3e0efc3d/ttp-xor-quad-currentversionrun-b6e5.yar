rule TTP_XOR_QUAD_CurrentVersionRun_b6e5 {
  strings:
    $key_b6e5 = { e5 8a [2] c1 84 [2] ea a8 [2] c4 8a [2] d0 91 [2] df 8b [2] c1 96 [2] c3 97 [2] d8 91 [2] c4 96 [2] d8 b9 }

  condition:
    any of them
}