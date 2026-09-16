rule TTP_XOR_QUAD_CurrentVersionRun_b6a6 {
  strings:
    $key_b6a6 = { e5 c9 [2] c1 c7 [2] ea eb [2] c4 c9 [2] d0 d2 [2] df c8 [2] c1 d5 [2] c3 d4 [2] d8 d2 [2] c4 d5 [2] d8 fa }

  condition:
    any of them
}