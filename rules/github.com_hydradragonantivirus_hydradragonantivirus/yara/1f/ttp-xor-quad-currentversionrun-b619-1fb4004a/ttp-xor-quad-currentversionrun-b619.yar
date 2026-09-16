rule TTP_XOR_QUAD_CurrentVersionRun_b619 {
  strings:
    $key_b619 = { e5 76 [2] c1 78 [2] ea 54 [2] c4 76 [2] d0 6d [2] df 77 [2] c1 6a [2] c3 6b [2] d8 6d [2] c4 6a [2] d8 45 }

  condition:
    any of them
}