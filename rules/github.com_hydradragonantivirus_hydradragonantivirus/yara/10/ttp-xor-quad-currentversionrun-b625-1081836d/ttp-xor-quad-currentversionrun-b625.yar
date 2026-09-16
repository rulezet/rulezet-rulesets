rule TTP_XOR_QUAD_CurrentVersionRun_b625 {
  strings:
    $key_b625 = { e5 4a [2] c1 44 [2] ea 68 [2] c4 4a [2] d0 51 [2] df 4b [2] c1 56 [2] c3 57 [2] d8 51 [2] c4 56 [2] d8 79 }

  condition:
    any of them
}