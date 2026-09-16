rule TTP_XOR_QUAD_CurrentVersionRun_b649 {
  strings:
    $key_b649 = { e5 26 [2] c1 28 [2] ea 04 [2] c4 26 [2] d0 3d [2] df 27 [2] c1 3a [2] c3 3b [2] d8 3d [2] c4 3a [2] d8 15 }

  condition:
    any of them
}