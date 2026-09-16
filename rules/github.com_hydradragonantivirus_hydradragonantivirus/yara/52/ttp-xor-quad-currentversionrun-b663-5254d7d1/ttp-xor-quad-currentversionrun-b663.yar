rule TTP_XOR_QUAD_CurrentVersionRun_b663 {
  strings:
    $key_b663 = { e5 0c [2] c1 02 [2] ea 2e [2] c4 0c [2] d0 17 [2] df 0d [2] c1 10 [2] c3 11 [2] d8 17 [2] c4 10 [2] d8 3f }

  condition:
    any of them
}