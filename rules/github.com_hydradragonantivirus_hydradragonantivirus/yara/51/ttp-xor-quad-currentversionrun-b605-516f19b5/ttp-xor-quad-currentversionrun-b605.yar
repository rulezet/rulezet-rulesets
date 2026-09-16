rule TTP_XOR_QUAD_CurrentVersionRun_b605 {
  strings:
    $key_b605 = { e5 6a [2] c1 64 [2] ea 48 [2] c4 6a [2] d0 71 [2] df 6b [2] c1 76 [2] c3 77 [2] d8 71 [2] c4 76 [2] d8 59 }

  condition:
    any of them
}