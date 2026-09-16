rule TTP_XOR_QUAD_CurrentVersionRun_b6b6 {
  strings:
    $key_b6b6 = { e5 d9 [2] c1 d7 [2] ea fb [2] c4 d9 [2] d0 c2 [2] df d8 [2] c1 c5 [2] c3 c4 [2] d8 c2 [2] c4 c5 [2] d8 ea }

  condition:
    any of them
}