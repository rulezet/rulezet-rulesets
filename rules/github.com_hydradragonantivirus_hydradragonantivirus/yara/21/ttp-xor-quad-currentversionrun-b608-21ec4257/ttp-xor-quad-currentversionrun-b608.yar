rule TTP_XOR_QUAD_CurrentVersionRun_b608 {
  strings:
    $key_b608 = { e5 67 [2] c1 69 [2] ea 45 [2] c4 67 [2] d0 7c [2] df 66 [2] c1 7b [2] c3 7a [2] d8 7c [2] c4 7b [2] d8 54 }

  condition:
    any of them
}