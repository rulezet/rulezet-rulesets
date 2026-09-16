rule TTP_XOR_QUAD_CurrentVersionRun_b636 {
  strings:
    $key_b636 = { e5 59 [2] c1 57 [2] ea 7b [2] c4 59 [2] d0 42 [2] df 58 [2] c1 45 [2] c3 44 [2] d8 42 [2] c4 45 [2] d8 6a }

  condition:
    any of them
}