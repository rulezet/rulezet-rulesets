rule TTP_XOR_QUAD_CurrentVersionRun_b6e8 {
  strings:
    $key_b6e8 = { e5 87 [2] c1 89 [2] ea a5 [2] c4 87 [2] d0 9c [2] df 86 [2] c1 9b [2] c3 9a [2] d8 9c [2] c4 9b [2] d8 b4 }

  condition:
    any of them
}