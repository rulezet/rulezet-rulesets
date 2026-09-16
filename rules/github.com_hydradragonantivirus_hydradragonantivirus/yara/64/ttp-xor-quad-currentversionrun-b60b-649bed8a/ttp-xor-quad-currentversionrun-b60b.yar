rule TTP_XOR_QUAD_CurrentVersionRun_b60b {
  strings:
    $key_b60b = { e5 64 [2] c1 6a [2] ea 46 [2] c4 64 [2] d0 7f [2] df 65 [2] c1 78 [2] c3 79 [2] d8 7f [2] c4 78 [2] d8 57 }

  condition:
    any of them
}