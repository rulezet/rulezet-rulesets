rule TTP_XOR_QUAD_CurrentVersionRun_b675 {
  strings:
    $key_b675 = { e5 1a [2] c1 14 [2] ea 38 [2] c4 1a [2] d0 01 [2] df 1b [2] c1 06 [2] c3 07 [2] d8 01 [2] c4 06 [2] d8 29 }

  condition:
    any of them
}