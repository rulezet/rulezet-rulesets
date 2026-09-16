rule TTP_XOR_QUAD_CurrentVersionRun_b623 {
  strings:
    $key_b623 = { e5 4c [2] c1 42 [2] ea 6e [2] c4 4c [2] d0 57 [2] df 4d [2] c1 50 [2] c3 51 [2] d8 57 [2] c4 50 [2] d8 7f }

  condition:
    any of them
}