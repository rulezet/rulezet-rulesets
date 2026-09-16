rule TTP_XOR_QUAD_CurrentVersionRun_b639 {
  strings:
    $key_b639 = { e5 56 [2] c1 58 [2] ea 74 [2] c4 56 [2] d0 4d [2] df 57 [2] c1 4a [2] c3 4b [2] d8 4d [2] c4 4a [2] d8 65 }

  condition:
    any of them
}